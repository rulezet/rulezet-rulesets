rule TTP_XOR_MULT_DOSStub_5980 {
  strings:
    $key_5980 = { 0d e8 [2] 79 f0 [2] 3e f2 [2] 79 e3 [2] 37 ef [2] 3b e5 [2] 2c ee [2] 37 a0 [2] 0a }

  condition:
    any of them
}