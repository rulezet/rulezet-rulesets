rule TTP_XOR_MULT_DOSStub_3c81 {
  strings:
    $key_3c81 = { 68 e9 [2] 1c f1 [2] 5b f3 [2] 1c e2 [2] 52 ee [2] 5e e4 [2] 49 ef [2] 52 a1 [2] 6f }

  condition:
    any of them
}