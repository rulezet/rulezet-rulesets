rule TTP_XOR_MULT_DOSStub_a6a1 {
  strings:
    $key_a6a1 = { f2 c9 [2] 86 d1 [2] c1 d3 [2] 86 c2 [2] c8 ce [2] c4 c4 [2] d3 cf [2] c8 81 [2] f5 }

  condition:
    any of them
}