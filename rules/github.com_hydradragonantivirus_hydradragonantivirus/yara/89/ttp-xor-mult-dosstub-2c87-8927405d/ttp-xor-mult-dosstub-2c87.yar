rule TTP_XOR_MULT_DOSStub_2c87 {
  strings:
    $key_2c87 = { 78 ef [2] 0c f7 [2] 4b f5 [2] 0c e4 [2] 42 e8 [2] 4e e2 [2] 59 e9 [2] 42 a7 [2] 7f }

  condition:
    any of them
}