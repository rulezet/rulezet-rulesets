rule TTP_XOR_MULT_DOSStub_bc87 {
  strings:
    $key_bc87 = { e8 ef [2] 9c f7 [2] db f5 [2] 9c e4 [2] d2 e8 [2] de e2 [2] c9 e9 [2] d2 a7 [2] ef }

  condition:
    any of them
}