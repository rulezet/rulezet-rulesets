rule TTP_XOR_MULT_DOSStub_4c86 {
  strings:
    $key_4c86 = { 18 ee [2] 6c f6 [2] 2b f4 [2] 6c e5 [2] 22 e9 [2] 2e e3 [2] 39 e8 [2] 22 a6 [2] 1f }

  condition:
    any of them
}