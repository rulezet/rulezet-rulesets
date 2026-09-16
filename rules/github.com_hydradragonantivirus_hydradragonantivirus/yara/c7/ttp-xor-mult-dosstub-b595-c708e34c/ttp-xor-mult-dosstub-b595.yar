rule TTP_XOR_MULT_DOSStub_b595 {
  strings:
    $key_b595 = { e1 fd [2] 95 e5 [2] d2 e7 [2] 95 f6 [2] db fa [2] d7 f0 [2] c0 fb [2] db b5 [2] e6 }

  condition:
    any of them
}