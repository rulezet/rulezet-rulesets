rule TTP_XOR_MULT_DOSStub_7375 {
  strings:
    $key_7375 = { 27 1d [2] 53 05 [2] 14 07 [2] 53 16 [2] 1d 1a [2] 11 10 [2] 06 1b [2] 1d 55 [2] 20 }

  condition:
    any of them
}