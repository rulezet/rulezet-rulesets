rule TTP_XOR_MULT_DOSStub_7449 {
  strings:
    $key_7449 = { 20 21 [2] 54 39 [2] 13 3b [2] 54 2a [2] 1a 26 [2] 16 2c [2] 01 27 [2] 1a 69 [2] 27 }

  condition:
    any of them
}