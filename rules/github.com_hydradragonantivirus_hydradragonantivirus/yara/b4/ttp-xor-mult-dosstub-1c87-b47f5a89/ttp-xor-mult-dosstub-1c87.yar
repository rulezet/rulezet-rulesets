rule TTP_XOR_MULT_DOSStub_1c87 {
  strings:
    $key_1c87 = { 48 ef [2] 3c f7 [2] 7b f5 [2] 3c e4 [2] 72 e8 [2] 7e e2 [2] 69 e9 [2] 72 a7 [2] 4f }

  condition:
    any of them
}