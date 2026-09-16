rule TTP_XOR_MULT_DOSStub_0ca1 {
  strings:
    $key_0ca1 = { 58 c9 [2] 2c d1 [2] 6b d3 [2] 2c c2 [2] 62 ce [2] 6e c4 [2] 79 cf [2] 62 81 [2] 5f }

  condition:
    any of them
}