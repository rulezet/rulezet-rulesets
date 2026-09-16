rule TTP_XOR_MULT_DOSStub_4c80 {
  strings:
    $key_4c80 = { 18 e8 [2] 6c f0 [2] 2b f2 [2] 6c e3 [2] 22 ef [2] 2e e5 [2] 39 ee [2] 22 a0 [2] 1f }

  condition:
    any of them
}