rule TTP_XOR_MULT_DOSStub_b3c3 {
  strings:
    $key_b3c3 = { e7 ab [2] 93 b3 [2] d4 b1 [2] 93 a0 [2] dd ac [2] d1 a6 [2] c6 ad [2] dd e3 [2] e0 }

  condition:
    any of them
}