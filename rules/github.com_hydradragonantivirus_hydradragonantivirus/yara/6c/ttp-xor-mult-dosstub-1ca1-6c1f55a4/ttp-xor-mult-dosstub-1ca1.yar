rule TTP_XOR_MULT_DOSStub_1ca1 {
  strings:
    $key_1ca1 = { 48 c9 [2] 3c d1 [2] 7b d3 [2] 3c c2 [2] 72 ce [2] 7e c4 [2] 69 cf [2] 72 81 [2] 4f }

  condition:
    any of them
}