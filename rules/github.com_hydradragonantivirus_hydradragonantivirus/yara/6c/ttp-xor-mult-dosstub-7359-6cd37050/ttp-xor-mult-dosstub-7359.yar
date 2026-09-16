rule TTP_XOR_MULT_DOSStub_7359 {
  strings:
    $key_7359 = { 27 31 [2] 53 29 [2] 14 2b [2] 53 3a [2] 1d 36 [2] 11 3c [2] 06 37 [2] 1d 79 [2] 20 }

  condition:
    any of them
}