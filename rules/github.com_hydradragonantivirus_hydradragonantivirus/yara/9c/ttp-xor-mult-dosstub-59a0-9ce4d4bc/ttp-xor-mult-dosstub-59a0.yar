rule TTP_XOR_MULT_DOSStub_59a0 {
  strings:
    $key_59a0 = { 0d c8 [2] 79 d0 [2] 3e d2 [2] 79 c3 [2] 37 cf [2] 3b c5 [2] 2c ce [2] 37 80 [2] 0a }

  condition:
    any of them
}