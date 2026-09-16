rule TTP_XOR_MULT_DOSStub_bc91 {
  strings:
    $key_bc91 = { e8 f9 [2] 9c e1 [2] db e3 [2] 9c f2 [2] d2 fe [2] de f4 [2] c9 ff [2] d2 b1 [2] ef }

  condition:
    any of them
}