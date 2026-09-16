rule TTP_XOR_MULT_DOSStub_0c81 {
  strings:
    $key_0c81 = { 58 e9 [2] 2c f1 [2] 6b f3 [2] 2c e2 [2] 62 ee [2] 6e e4 [2] 79 ef [2] 62 a1 [2] 5f }

  condition:
    any of them
}