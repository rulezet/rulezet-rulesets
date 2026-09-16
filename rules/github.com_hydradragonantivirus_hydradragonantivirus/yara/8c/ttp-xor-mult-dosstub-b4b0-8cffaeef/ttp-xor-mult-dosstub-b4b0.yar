rule TTP_XOR_MULT_DOSStub_b4b0 {
  strings:
    $key_b4b0 = { e0 d8 [2] 94 c0 [2] d3 c2 [2] 94 d3 [2] da df [2] d6 d5 [2] c1 de [2] da 90 [2] e7 }

  condition:
    any of them
}