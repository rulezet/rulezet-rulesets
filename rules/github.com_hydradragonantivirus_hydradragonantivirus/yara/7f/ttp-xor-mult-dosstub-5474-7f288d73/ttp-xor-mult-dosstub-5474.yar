rule TTP_XOR_MULT_DOSStub_5474 {
  strings:
    $key_5474 = { 00 1c [2] 74 04 [2] 33 06 [2] 74 17 [2] 3a 1b [2] 36 11 [2] 21 1a [2] 3a 54 [2] 07 }

  condition:
    any of them
}