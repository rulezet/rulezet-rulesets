rule TTP_XOR_MULT_DOSStub_78c7 {
  strings:
    $key_78c7 = { 2c af [2] 58 b7 [2] 1f b5 [2] 58 a4 [2] 16 a8 [2] 1a a2 [2] 0d a9 [2] 16 e7 [2] 2b }

  condition:
    any of them
}