rule TTP_XOR_MULT_DOSStub_a1d2 {
  strings:
    $key_a1d2 = { f5 ba [2] 81 a2 [2] c6 a0 [2] 81 b1 [2] cf bd [2] c3 b7 [2] d4 bc [2] cf f2 [2] f2 }

  condition:
    any of them
}