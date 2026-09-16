rule TTP_XOR_MULT_DOSStub_b495 {
  strings:
    $key_b495 = { e0 fd [2] 94 e5 [2] d3 e7 [2] 94 f6 [2] da fa [2] d6 f0 [2] c1 fb [2] da b5 [2] e7 }

  condition:
    any of them
}