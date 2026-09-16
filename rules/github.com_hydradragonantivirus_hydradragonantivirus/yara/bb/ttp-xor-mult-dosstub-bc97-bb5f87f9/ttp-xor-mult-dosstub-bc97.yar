rule TTP_XOR_MULT_DOSStub_bc97 {
  strings:
    $key_bc97 = { e8 ff [2] 9c e7 [2] db e5 [2] 9c f4 [2] d2 f8 [2] de f2 [2] c9 f9 [2] d2 b7 [2] ef }

  condition:
    any of them
}