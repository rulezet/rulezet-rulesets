rule TTP_XOR_MULT_DOSStub_85b6 {
  strings:
    $key_85b6 = { d1 de [2] a5 c6 [2] e2 c4 [2] a5 d5 [2] eb d9 [2] e7 d3 [2] f0 d8 [2] eb 96 [2] d6 }

  condition:
    any of them
}