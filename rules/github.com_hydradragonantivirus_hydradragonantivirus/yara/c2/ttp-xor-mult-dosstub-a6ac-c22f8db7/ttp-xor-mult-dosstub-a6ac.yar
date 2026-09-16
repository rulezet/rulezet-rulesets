rule TTP_XOR_MULT_DOSStub_a6ac {
  strings:
    $key_a6ac = { f2 c4 [2] 86 dc [2] c1 de [2] 86 cf [2] c8 c3 [2] c4 c9 [2] d3 c2 [2] c8 8c [2] f5 }

  condition:
    any of them
}