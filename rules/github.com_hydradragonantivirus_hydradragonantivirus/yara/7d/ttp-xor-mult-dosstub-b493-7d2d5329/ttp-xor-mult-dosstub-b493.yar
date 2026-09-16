rule TTP_XOR_MULT_DOSStub_b493 {
  strings:
    $key_b493 = { e0 fb [2] 94 e3 [2] d3 e1 [2] 94 f0 [2] da fc [2] d6 f6 [2] c1 fd [2] da b3 [2] e7 }

  condition:
    any of them
}