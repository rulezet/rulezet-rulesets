rule TTP_XOR_MULT_DOSStub_b4d2 {
  strings:
    $key_b4d2 = { e0 ba [2] 94 a2 [2] d3 a0 [2] 94 b1 [2] da bd [2] d6 b7 [2] c1 bc [2] da f2 [2] e7 }

  condition:
    any of them
}