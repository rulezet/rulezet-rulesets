rule TTP_XOR_MULT_DOSStub_bc92 {
  strings:
    $key_bc92 = { e8 fa [2] 9c e2 [2] db e0 [2] 9c f1 [2] d2 fd [2] de f7 [2] c9 fc [2] d2 b2 [2] ef }

  condition:
    any of them
}