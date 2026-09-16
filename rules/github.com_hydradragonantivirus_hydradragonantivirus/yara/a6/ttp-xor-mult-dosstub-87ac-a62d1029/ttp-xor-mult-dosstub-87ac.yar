rule TTP_XOR_MULT_DOSStub_87ac {
  strings:
    $key_87ac = { d3 c4 [2] a7 dc [2] e0 de [2] a7 cf [2] e9 c3 [2] e5 c9 [2] f2 c2 [2] e9 8c [2] d4 }

  condition:
    any of them
}