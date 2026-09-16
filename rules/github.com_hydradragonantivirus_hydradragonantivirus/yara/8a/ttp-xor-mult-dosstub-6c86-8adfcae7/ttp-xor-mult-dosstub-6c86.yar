rule TTP_XOR_MULT_DOSStub_6c86 {
  strings:
    $key_6c86 = { 38 ee [2] 4c f6 [2] 0b f4 [2] 4c e5 [2] 02 e9 [2] 0e e3 [2] 19 e8 [2] 02 a6 [2] 3f }

  condition:
    any of them
}