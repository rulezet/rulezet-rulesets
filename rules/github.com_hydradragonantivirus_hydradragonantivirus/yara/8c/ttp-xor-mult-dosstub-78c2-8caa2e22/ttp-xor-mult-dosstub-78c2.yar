rule TTP_XOR_MULT_DOSStub_78c2 {
  strings:
    $key_78c2 = { 2c aa [2] 58 b2 [2] 1f b0 [2] 58 a1 [2] 16 ad [2] 1a a7 [2] 0d ac [2] 16 e2 [2] 2b }

  condition:
    any of them
}