rule TTP_XOR_MULT_DOSStub_78c1 {
  strings:
    $key_78c1 = { 2c a9 [2] 58 b1 [2] 1f b3 [2] 58 a2 [2] 16 ae [2] 1a a4 [2] 0d af [2] 16 e1 [2] 2b }

  condition:
    any of them
}