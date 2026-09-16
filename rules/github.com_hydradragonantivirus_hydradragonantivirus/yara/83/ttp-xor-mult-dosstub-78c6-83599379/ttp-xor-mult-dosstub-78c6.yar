rule TTP_XOR_MULT_DOSStub_78c6 {
  strings:
    $key_78c6 = { 2c ae [2] 58 b6 [2] 1f b4 [2] 58 a5 [2] 16 a9 [2] 1a a3 [2] 0d a8 [2] 16 e6 [2] 2b }

  condition:
    any of them
}