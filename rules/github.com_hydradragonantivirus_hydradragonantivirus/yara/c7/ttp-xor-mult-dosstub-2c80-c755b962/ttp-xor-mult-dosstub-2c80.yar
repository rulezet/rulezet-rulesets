rule TTP_XOR_MULT_DOSStub_2c80 {
  strings:
    $key_2c80 = { 78 e8 [2] 0c f0 [2] 4b f2 [2] 0c e3 [2] 42 ef [2] 4e e5 [2] 59 ee [2] 42 a0 [2] 7f }

  condition:
    any of them
}