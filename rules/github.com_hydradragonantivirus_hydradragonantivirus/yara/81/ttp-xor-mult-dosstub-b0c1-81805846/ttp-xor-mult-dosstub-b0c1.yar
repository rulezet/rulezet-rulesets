rule TTP_XOR_MULT_DOSStub_b0c1 {
  strings:
    $key_b0c1 = { e4 a9 [2] 90 b1 [2] d7 b3 [2] 90 a2 [2] de ae [2] d2 a4 [2] c5 af [2] de e1 [2] e3 }

  condition:
    any of them
}