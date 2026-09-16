rule TTP_XOR_MULT_DOSStub_5449 {
  strings:
    $key_5449 = { 00 21 [2] 74 39 [2] 33 3b [2] 74 2a [2] 3a 26 [2] 36 2c [2] 21 27 [2] 3a 69 [2] 07 }

  condition:
    any of them
}