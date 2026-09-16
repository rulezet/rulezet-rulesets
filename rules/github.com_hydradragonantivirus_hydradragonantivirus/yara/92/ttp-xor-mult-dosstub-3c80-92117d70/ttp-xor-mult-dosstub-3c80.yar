rule TTP_XOR_MULT_DOSStub_3c80 {
  strings:
    $key_3c80 = { 68 e8 [2] 1c f0 [2] 5b f2 [2] 1c e3 [2] 52 ef [2] 5e e5 [2] 49 ee [2] 52 a0 [2] 6f }

  condition:
    any of them
}