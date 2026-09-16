rule TTP_XOR_MULT_DOSStub_bc88 {
  strings:
    $key_bc88 = { e8 e0 [2] 9c f8 [2] db fa [2] 9c eb [2] d2 e7 [2] de ed [2] c9 e6 [2] d2 a8 [2] ef }

  condition:
    any of them
}