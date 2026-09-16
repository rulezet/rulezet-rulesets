rule TTP_XOR_MULT_DOSStub_b0d0 {
  strings:
    $key_b0d0 = { e4 b8 [2] 90 a0 [2] d7 a2 [2] 90 b3 [2] de bf [2] d2 b5 [2] c5 be [2] de f0 [2] e3 }

  condition:
    any of them
}