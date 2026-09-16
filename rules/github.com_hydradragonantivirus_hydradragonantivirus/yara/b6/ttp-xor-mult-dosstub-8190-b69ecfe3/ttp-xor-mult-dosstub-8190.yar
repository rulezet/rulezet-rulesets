rule TTP_XOR_MULT_DOSStub_8190 {
  strings:
    $key_8190 = { d5 f8 [2] a1 e0 [2] e6 e2 [2] a1 f3 [2] ef ff [2] e3 f5 [2] f4 fe [2] ef b0 [2] d2 }

  condition:
    any of them
}