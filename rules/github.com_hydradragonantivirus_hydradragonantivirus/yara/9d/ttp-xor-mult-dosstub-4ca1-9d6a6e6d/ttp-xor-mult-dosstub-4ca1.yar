rule TTP_XOR_MULT_DOSStub_4ca1 {
  strings:
    $key_4ca1 = { 18 c9 [2] 6c d1 [2] 2b d3 [2] 6c c2 [2] 22 ce [2] 2e c4 [2] 39 cf [2] 22 81 [2] 1f }

  condition:
    any of them
}