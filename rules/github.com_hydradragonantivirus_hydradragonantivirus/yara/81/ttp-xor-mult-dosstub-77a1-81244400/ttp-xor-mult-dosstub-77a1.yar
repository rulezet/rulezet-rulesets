rule TTP_XOR_MULT_DOSStub_77a1 {
  strings:
    $key_77a1 = { 23 c9 [2] 57 d1 [2] 10 d3 [2] 57 c2 [2] 19 ce [2] 15 c4 [2] 02 cf [2] 19 81 [2] 24 }

  condition:
    any of them
}