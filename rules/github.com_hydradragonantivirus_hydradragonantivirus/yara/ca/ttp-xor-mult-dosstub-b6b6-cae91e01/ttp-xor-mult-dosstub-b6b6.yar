rule TTP_XOR_MULT_DOSStub_b6b6 {
  strings:
    $key_b6b6 = { e2 de [2] 96 c6 [2] d1 c4 [2] 96 d5 [2] d8 d9 [2] d4 d3 [2] c3 d8 [2] d8 96 [2] e5 }

  condition:
    any of them
}