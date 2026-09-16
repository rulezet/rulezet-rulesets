rule TTP_XOR_MULT_DOSStub_b3b6 {
  strings:
    $key_b3b6 = { e7 de [2] 93 c6 [2] d4 c4 [2] 93 d5 [2] dd d9 [2] d1 d3 [2] c6 d8 [2] dd 96 [2] e0 }

  condition:
    any of them
}