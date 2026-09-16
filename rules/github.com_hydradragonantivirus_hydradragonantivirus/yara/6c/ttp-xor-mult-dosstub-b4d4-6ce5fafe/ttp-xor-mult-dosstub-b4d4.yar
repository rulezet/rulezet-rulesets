rule TTP_XOR_MULT_DOSStub_b4d4 {
  strings:
    $key_b4d4 = { e0 bc [2] 94 a4 [2] d3 a6 [2] 94 b7 [2] da bb [2] d6 b1 [2] c1 ba [2] da f4 [2] e7 }

  condition:
    any of them
}