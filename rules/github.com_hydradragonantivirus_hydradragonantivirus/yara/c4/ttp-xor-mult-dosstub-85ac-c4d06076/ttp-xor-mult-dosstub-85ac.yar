rule TTP_XOR_MULT_DOSStub_85ac {
  strings:
    $key_85ac = { d1 c4 [2] a5 dc [2] e2 de [2] a5 cf [2] eb c3 [2] e7 c9 [2] f0 c2 [2] eb 8c [2] d6 }

  condition:
    any of them
}