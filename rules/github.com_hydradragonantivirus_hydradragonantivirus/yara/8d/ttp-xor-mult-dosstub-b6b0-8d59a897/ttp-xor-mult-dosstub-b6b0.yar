rule TTP_XOR_MULT_DOSStub_b6b0 {
  strings:
    $key_b6b0 = { e2 d8 [2] 96 c0 [2] d1 c2 [2] 96 d3 [2] d8 df [2] d4 d5 [2] c3 de [2] d8 90 [2] e5 }

  condition:
    any of them
}