rule TTP_XOR_MULT_DOSStub_1fa1 {
  strings:
    $key_1fa1 = { 4b c9 [2] 3f d1 [2] 78 d3 [2] 3f c2 [2] 71 ce [2] 7d c4 [2] 6a cf [2] 71 81 [2] 4c }

  condition:
    any of them
}