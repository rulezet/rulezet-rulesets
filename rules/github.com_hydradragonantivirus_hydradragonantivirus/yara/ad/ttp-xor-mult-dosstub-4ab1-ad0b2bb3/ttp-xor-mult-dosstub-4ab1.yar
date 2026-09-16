rule TTP_XOR_MULT_DOSStub_4ab1 {
  strings:
    $key_4ab1 = { 1e d9 [2] 6a c1 [2] 2d c3 [2] 6a d2 [2] 24 de [2] 28 d4 [2] 3f df [2] 24 91 [2] 19 }

  condition:
    any of them
}