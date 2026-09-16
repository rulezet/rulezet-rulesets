rule TTP_XOR_MULT_DOSStub_5ab1 {
  strings:
    $key_5ab1 = { 0e d9 [2] 7a c1 [2] 3d c3 [2] 7a d2 [2] 34 de [2] 38 d4 [2] 2f df [2] 34 91 [2] 09 }

  condition:
    any of them
}