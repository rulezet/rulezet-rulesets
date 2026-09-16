rule TTP_XOR_MULT_DOSStub_b589 {
  strings:
    $key_b589 = { e1 e1 [2] 95 f9 [2] d2 fb [2] 95 ea [2] db e6 [2] d7 ec [2] c0 e7 [2] db a9 [2] e6 }

  condition:
    any of them
}