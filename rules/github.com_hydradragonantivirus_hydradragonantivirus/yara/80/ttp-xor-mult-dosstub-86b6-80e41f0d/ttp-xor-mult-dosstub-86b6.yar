rule TTP_XOR_MULT_DOSStub_86b6 {
  strings:
    $key_86b6 = { d2 de [2] a6 c6 [2] e1 c4 [2] a6 d5 [2] e8 d9 [2] e4 d3 [2] f3 d8 [2] e8 96 [2] d5 }

  condition:
    any of them
}