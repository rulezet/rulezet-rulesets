rule TTP_XOR_MULT_DOSStub_74a1 {
  strings:
    $key_74a1 = { 20 c9 [2] 54 d1 [2] 13 d3 [2] 54 c2 [2] 1a ce [2] 16 c4 [2] 01 cf [2] 1a 81 [2] 27 }

  condition:
    any of them
}