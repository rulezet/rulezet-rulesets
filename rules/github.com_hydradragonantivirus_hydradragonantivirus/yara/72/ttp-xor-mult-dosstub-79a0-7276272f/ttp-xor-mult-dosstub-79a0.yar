rule TTP_XOR_MULT_DOSStub_79a0 {
  strings:
    $key_79a0 = { 2d c8 [2] 59 d0 [2] 1e d2 [2] 59 c3 [2] 17 cf [2] 1b c5 [2] 0c ce [2] 17 80 [2] 2a }

  condition:
    any of them
}