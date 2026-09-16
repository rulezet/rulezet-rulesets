rule TTP_XOR_MULT_DOSStub_bc93 {
  strings:
    $key_bc93 = { e8 fb [2] 9c e3 [2] db e1 [2] 9c f0 [2] d2 fc [2] de f6 [2] c9 fd [2] d2 b3 [2] ef }

  condition:
    any of them
}