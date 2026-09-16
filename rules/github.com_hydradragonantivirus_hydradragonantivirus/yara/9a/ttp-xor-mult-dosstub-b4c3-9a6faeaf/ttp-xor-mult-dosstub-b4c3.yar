rule TTP_XOR_MULT_DOSStub_b4c3 {
  strings:
    $key_b4c3 = { e0 ab [2] 94 b3 [2] d3 b1 [2] 94 a0 [2] da ac [2] d6 a6 [2] c1 ad [2] da e3 [2] e7 }

  condition:
    any of them
}