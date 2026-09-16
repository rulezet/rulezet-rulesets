rule TTP_XOR_MULT_DOSStub_1c80 {
  strings:
    $key_1c80 = { 48 e8 [2] 3c f0 [2] 7b f2 [2] 3c e3 [2] 72 ef [2] 7e e5 [2] 69 ee [2] 72 a0 [2] 4f }

  condition:
    any of them
}