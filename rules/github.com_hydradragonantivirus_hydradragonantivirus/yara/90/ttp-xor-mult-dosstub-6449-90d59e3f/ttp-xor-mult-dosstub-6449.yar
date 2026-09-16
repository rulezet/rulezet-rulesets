rule TTP_XOR_MULT_DOSStub_6449 {
  strings:
    $key_6449 = { 30 21 [2] 44 39 [2] 03 3b [2] 44 2a [2] 0a 26 [2] 06 2c [2] 11 27 [2] 0a 69 [2] 37 }

  condition:
    any of them
}