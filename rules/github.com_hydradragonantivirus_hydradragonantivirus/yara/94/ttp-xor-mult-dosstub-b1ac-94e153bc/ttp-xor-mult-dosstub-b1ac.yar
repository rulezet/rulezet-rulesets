rule TTP_XOR_MULT_DOSStub_b1ac {
  strings:
    $key_b1ac = { e5 c4 [2] 91 dc [2] d6 de [2] 91 cf [2] df c3 [2] d3 c9 [2] c4 c2 [2] df 8c [2] e2 }

  condition:
    any of them
}