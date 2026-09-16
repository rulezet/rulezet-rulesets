rule TTP_XOR_MULT_DOSStub_b58b {
  strings:
    $key_b58b = { e1 e3 [2] 95 fb [2] d2 f9 [2] 95 e8 [2] db e4 [2] d7 ee [2] c0 e5 [2] db ab [2] e6 }

  condition:
    any of them
}