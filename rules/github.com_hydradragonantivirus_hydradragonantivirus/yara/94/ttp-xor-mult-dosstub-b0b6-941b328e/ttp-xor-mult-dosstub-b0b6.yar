rule TTP_XOR_MULT_DOSStub_b0b6 {
  strings:
    $key_b0b6 = { e4 de [2] 90 c6 [2] d7 c4 [2] 90 d5 [2] de d9 [2] d2 d3 [2] c5 d8 [2] de 96 [2] e3 }

  condition:
    any of them
}