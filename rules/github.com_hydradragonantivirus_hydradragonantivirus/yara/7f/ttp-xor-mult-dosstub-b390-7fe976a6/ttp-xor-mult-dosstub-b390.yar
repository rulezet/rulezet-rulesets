rule TTP_XOR_MULT_DOSStub_b390 {
  strings:
    $key_b390 = { e7 f8 [2] 93 e0 [2] d4 e2 [2] 93 f3 [2] dd ff [2] d1 f5 [2] c6 fe [2] dd b0 [2] e0 }

  condition:
    any of them
}