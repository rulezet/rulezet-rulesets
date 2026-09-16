rule TTP_XOR_MULT_DOSStub_d5a7 {
  strings:
    $key_d5a7 = { 81 cf [2] f5 d7 [2] b2 d5 [2] f5 c4 [2] bb c8 [2] b7 c2 [2] a0 c9 [2] bb 87 [2] 86 }

  condition:
    any of them
}