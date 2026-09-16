rule TTP_XOR_MULT_DOSStub_b0d6 {
  strings:
    $key_b0d6 = { e4 be [2] 90 a6 [2] d7 a4 [2] 90 b5 [2] de b9 [2] d2 b3 [2] c5 b8 [2] de f6 [2] e3 }

  condition:
    any of them
}