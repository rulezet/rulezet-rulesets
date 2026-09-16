rule TTP_XOR_MULT_DOSStub_a7a1 {
  strings:
    $key_a7a1 = { f3 c9 [2] 87 d1 [2] c0 d3 [2] 87 c2 [2] c9 ce [2] c5 c4 [2] d2 cf [2] c9 81 [2] f4 }

  condition:
    any of them
}