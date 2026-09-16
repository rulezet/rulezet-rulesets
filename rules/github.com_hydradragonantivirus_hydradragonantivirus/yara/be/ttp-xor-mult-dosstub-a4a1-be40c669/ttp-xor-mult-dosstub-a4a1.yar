rule TTP_XOR_MULT_DOSStub_a4a1 {
  strings:
    $key_a4a1 = { f0 c9 [2] 84 d1 [2] c3 d3 [2] 84 c2 [2] ca ce [2] c6 c4 [2] d1 cf [2] ca 81 [2] f7 }

  condition:
    any of them
}