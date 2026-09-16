rule TTP_XOR_MULT_DOSStub_81b6 {
  strings:
    $key_81b6 = { d5 de [2] a1 c6 [2] e6 c4 [2] a1 d5 [2] ef d9 [2] e3 d3 [2] f4 d8 [2] ef 96 [2] d2 }

  condition:
    any of them
}