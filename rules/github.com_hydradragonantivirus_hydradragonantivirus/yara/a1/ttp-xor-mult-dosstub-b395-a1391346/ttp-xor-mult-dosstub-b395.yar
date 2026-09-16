rule TTP_XOR_MULT_DOSStub_b395 {
  strings:
    $key_b395 = { e7 fd [2] 93 e5 [2] d4 e7 [2] 93 f6 [2] dd fa [2] d1 f0 [2] c6 fb [2] dd b5 [2] e0 }

  condition:
    any of them
}