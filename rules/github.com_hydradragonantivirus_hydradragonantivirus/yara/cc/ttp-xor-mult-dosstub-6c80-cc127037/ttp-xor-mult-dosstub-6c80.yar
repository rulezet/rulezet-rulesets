rule TTP_XOR_MULT_DOSStub_6c80 {
  strings:
    $key_6c80 = { 38 e8 [2] 4c f0 [2] 0b f2 [2] 4c e3 [2] 02 ef [2] 0e e5 [2] 19 ee [2] 02 a0 [2] 3f }

  condition:
    any of them
}