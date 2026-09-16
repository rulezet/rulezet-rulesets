rule TTP_XOR_MULT_DOSStub_b4b6 {
  strings:
    $key_b4b6 = { e0 de [2] 94 c6 [2] d3 c4 [2] 94 d5 [2] da d9 [2] d6 d3 [2] c1 d8 [2] da 96 [2] e7 }

  condition:
    any of them
}