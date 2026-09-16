rule TTP_XOR_MULT_DOSStub_40a1 {
  strings:
    $key_40a1 = { 14 c9 [2] 60 d1 [2] 27 d3 [2] 60 c2 [2] 2e ce [2] 22 c4 [2] 35 cf [2] 2e 81 [2] 13 }

  condition:
    any of them
}