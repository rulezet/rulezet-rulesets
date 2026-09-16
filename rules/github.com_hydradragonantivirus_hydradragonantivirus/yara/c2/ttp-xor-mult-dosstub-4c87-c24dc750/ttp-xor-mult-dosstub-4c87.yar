rule TTP_XOR_MULT_DOSStub_4c87 {
  strings:
    $key_4c87 = { 18 ef [2] 6c f7 [2] 2b f5 [2] 6c e4 [2] 22 e8 [2] 2e e2 [2] 39 e9 [2] 22 a7 [2] 1f }

  condition:
    any of them
}