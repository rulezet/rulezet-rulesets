rule TTP_XOR_MULT_DOSStub_13a1 {
  strings:
    $key_13a1 = { 47 c9 [2] 33 d1 [2] 74 d3 [2] 33 c2 [2] 7d ce [2] 71 c4 [2] 66 cf [2] 7d 81 [2] 40 }

  condition:
    any of them
}