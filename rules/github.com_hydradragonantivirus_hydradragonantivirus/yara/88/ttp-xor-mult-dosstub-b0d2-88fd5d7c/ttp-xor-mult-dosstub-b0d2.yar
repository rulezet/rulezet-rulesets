rule TTP_XOR_MULT_DOSStub_b0d2 {
  strings:
    $key_b0d2 = { e4 ba [2] 90 a2 [2] d7 a0 [2] 90 b1 [2] de bd [2] d2 b7 [2] c5 bc [2] de f2 [2] e3 }

  condition:
    any of them
}