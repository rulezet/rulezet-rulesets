rule TTP_XOR_MULT_DOSStub_8196 {
  strings:
    $key_8196 = { d5 fe [2] a1 e6 [2] e6 e4 [2] a1 f5 [2] ef f9 [2] e3 f3 [2] f4 f8 [2] ef b6 [2] d2 }

  condition:
    any of them
}