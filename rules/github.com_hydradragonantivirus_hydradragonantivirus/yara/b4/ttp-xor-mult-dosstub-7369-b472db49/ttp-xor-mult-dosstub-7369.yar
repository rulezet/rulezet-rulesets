rule TTP_XOR_MULT_DOSStub_7369 {
  strings:
    $key_7369 = { 27 01 [2] 53 19 [2] 14 1b [2] 53 0a [2] 1d 06 [2] 11 0c [2] 06 07 [2] 1d 49 [2] 20 }

  condition:
    any of them
}