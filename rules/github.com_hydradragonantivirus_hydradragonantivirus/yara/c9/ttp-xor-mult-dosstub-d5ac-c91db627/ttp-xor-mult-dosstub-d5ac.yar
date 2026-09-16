rule TTP_XOR_MULT_DOSStub_d5ac {
  strings:
    $key_d5ac = { 81 c4 [2] f5 dc [2] b2 de [2] f5 cf [2] bb c3 [2] b7 c9 [2] a0 c2 [2] bb 8c [2] 86 }

  condition:
    any of them
}