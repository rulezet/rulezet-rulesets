rule TTP_XOR_MULT_DOSStub_bc94 {
  strings:
    $key_bc94 = { e8 fc [2] 9c e4 [2] db e6 [2] 9c f7 [2] d2 fb [2] de f1 [2] c9 fa [2] d2 b4 [2] ef }

  condition:
    any of them
}