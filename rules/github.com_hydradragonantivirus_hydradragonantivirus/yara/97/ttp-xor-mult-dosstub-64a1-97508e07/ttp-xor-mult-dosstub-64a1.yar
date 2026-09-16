rule TTP_XOR_MULT_DOSStub_64a1 {
  strings:
    $key_64a1 = { 30 c9 [2] 44 d1 [2] 03 d3 [2] 44 c2 [2] 0a ce [2] 06 c4 [2] 11 cf [2] 0a 81 [2] 37 }

  condition:
    any of them
}