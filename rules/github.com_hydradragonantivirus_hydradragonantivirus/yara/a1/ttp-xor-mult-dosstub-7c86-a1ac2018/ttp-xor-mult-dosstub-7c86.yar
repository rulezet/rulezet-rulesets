rule TTP_XOR_MULT_DOSStub_7c86 {
  strings:
    $key_7c86 = { 28 ee [2] 5c f6 [2] 1b f4 [2] 5c e5 [2] 12 e9 [2] 1e e3 [2] 09 e8 [2] 12 a6 [2] 2f }

  condition:
    any of them
}