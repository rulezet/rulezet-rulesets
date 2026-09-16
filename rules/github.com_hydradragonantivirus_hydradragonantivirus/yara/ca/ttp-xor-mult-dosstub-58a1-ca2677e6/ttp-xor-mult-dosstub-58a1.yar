rule TTP_XOR_MULT_DOSStub_58a1 {
  strings:
    $key_58a1 = { 0c c9 [2] 78 d1 [2] 3f d3 [2] 78 c2 [2] 36 ce [2] 3a c4 [2] 2d cf [2] 36 81 [2] 0b }

  condition:
    any of them
}