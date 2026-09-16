rule TTP_XOR_MULT_DOSStub_b0c3 {
  strings:
    $key_b0c3 = { e4 ab [2] 90 b3 [2] d7 b1 [2] 90 a0 [2] de ac [2] d2 a6 [2] c5 ad [2] de e3 [2] e3 }

  condition:
    any of them
}