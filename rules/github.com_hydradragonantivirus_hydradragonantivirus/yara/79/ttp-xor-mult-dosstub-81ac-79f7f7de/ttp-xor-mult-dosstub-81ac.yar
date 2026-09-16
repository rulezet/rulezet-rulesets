rule TTP_XOR_MULT_DOSStub_81ac {
  strings:
    $key_81ac = { d5 c4 [2] a1 dc [2] e6 de [2] a1 cf [2] ef c3 [2] e3 c9 [2] f4 c2 [2] ef 8c [2] d2 }

  condition:
    any of them
}