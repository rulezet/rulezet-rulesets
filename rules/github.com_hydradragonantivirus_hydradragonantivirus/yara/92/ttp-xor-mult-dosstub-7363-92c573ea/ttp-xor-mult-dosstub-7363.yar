rule TTP_XOR_MULT_DOSStub_7363 {
  strings:
    $key_7363 = { 27 0b [2] 53 13 [2] 14 11 [2] 53 00 [2] 1d 0c [2] 11 06 [2] 06 0d [2] 1d 43 [2] 20 }

  condition:
    any of them
}