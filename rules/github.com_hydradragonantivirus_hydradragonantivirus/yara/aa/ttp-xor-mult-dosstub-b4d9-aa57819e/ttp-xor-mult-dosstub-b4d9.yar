rule TTP_XOR_MULT_DOSStub_b4d9 {
  strings:
    $key_b4d9 = { e0 b1 [2] 94 a9 [2] d3 ab [2] 94 ba [2] da b6 [2] d6 bc [2] c1 b7 [2] da f9 [2] e7 }

  condition:
    any of them
}