rule TTP_XOR_MULT_DOSStub_0c87 {
  strings:
    $key_0c87 = { 58 ef [2] 2c f7 [2] 6b f5 [2] 2c e4 [2] 62 e8 [2] 6e e2 [2] 79 e9 [2] 62 a7 [2] 5f }

  condition:
    any of them
}