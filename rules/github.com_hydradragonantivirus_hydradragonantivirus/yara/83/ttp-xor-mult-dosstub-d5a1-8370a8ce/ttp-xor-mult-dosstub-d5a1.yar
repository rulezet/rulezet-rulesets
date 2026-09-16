rule TTP_XOR_MULT_DOSStub_d5a1 {
  strings:
    $key_d5a1 = { 81 c9 [2] f5 d1 [2] b2 d3 [2] f5 c2 [2] bb ce [2] b7 c4 [2] a0 cf [2] bb 81 [2] 86 }

  condition:
    any of them
}