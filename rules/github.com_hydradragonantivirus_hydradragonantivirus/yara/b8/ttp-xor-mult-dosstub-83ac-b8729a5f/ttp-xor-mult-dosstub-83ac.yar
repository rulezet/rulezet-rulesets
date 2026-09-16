rule TTP_XOR_MULT_DOSStub_83ac {
  strings:
    $key_83ac = { d7 c4 [2] a3 dc [2] e4 de [2] a3 cf [2] ed c3 [2] e1 c9 [2] f6 c2 [2] ed 8c [2] d0 }

  condition:
    any of them
}