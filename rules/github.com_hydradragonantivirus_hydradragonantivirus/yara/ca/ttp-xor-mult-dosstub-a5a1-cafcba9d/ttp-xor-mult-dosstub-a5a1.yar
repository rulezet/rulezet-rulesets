rule TTP_XOR_MULT_DOSStub_a5a1 {
  strings:
    $key_a5a1 = { f1 c9 [2] 85 d1 [2] c2 d3 [2] 85 c2 [2] cb ce [2] c7 c4 [2] d0 cf [2] cb 81 [2] f6 }

  condition:
    any of them
}