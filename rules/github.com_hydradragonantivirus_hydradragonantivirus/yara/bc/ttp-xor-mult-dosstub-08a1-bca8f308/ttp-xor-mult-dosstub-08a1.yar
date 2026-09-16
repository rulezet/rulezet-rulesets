rule TTP_XOR_MULT_DOSStub_08a1 {
  strings:
    $key_08a1 = { 5c c9 [2] 28 d1 [2] 6f d3 [2] 28 c2 [2] 66 ce [2] 6a c4 [2] 7d cf [2] 66 81 [2] 5b }

  condition:
    any of them
}