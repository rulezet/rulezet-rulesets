rule TTP_XOR_MULT_DOSStub_5c81 {
  strings:
    $key_5c81 = { 08 e9 [2] 7c f1 [2] 3b f3 [2] 7c e2 [2] 32 ee [2] 3e e4 [2] 29 ef [2] 32 a1 [2] 0f }

  condition:
    any of them
}