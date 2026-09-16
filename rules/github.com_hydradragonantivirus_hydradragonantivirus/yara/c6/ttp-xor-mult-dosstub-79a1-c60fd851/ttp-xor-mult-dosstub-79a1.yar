rule TTP_XOR_MULT_DOSStub_79a1 {
  strings:
    $key_79a1 = { 2d c9 [2] 59 d1 [2] 1e d3 [2] 59 c2 [2] 17 ce [2] 1b c4 [2] 0c cf [2] 17 81 [2] 2a }

  condition:
    any of them
}