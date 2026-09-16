rule TTP_XOR_MULT_DOSStub_04a1 {
  strings:
    $key_04a1 = { 50 c9 [2] 24 d1 [2] 63 d3 [2] 24 c2 [2] 6a ce [2] 66 c4 [2] 71 cf [2] 6a 81 [2] 57 }

  condition:
    any of them
}