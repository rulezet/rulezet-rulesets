rule TTP_XOR_MULT_DOSStub_52a1 {
  strings:
    $key_52a1 = { 06 c9 [2] 72 d1 [2] 35 d3 [2] 72 c2 [2] 3c ce [2] 30 c4 [2] 27 cf [2] 3c 81 [2] 01 }

  condition:
    any of them
}