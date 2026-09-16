rule TTP_XOR_MULT_DOSStub_a1b6 {
  strings:
    $key_a1b6 = { f5 de [2] 81 c6 [2] c6 c4 [2] 81 d5 [2] cf d9 [2] c3 d3 [2] d4 d8 [2] cf 96 [2] f2 }

  condition:
    any of them
}