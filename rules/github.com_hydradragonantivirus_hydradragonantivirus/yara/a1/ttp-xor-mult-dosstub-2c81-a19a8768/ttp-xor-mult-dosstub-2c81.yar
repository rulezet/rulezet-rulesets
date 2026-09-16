rule TTP_XOR_MULT_DOSStub_2c81 {
  strings:
    $key_2c81 = { 78 e9 [2] 0c f1 [2] 4b f3 [2] 0c e2 [2] 42 ee [2] 4e e4 [2] 59 ef [2] 42 a1 [2] 7f }

  condition:
    any of them
}