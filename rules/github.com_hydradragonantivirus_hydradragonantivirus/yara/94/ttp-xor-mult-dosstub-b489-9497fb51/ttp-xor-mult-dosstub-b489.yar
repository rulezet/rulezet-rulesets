rule TTP_XOR_MULT_DOSStub_b489 {
  strings:
    $key_b489 = { e0 e1 [2] 94 f9 [2] d3 fb [2] 94 ea [2] da e6 [2] d6 ec [2] c1 e7 [2] da a9 [2] e7 }

  condition:
    any of them
}