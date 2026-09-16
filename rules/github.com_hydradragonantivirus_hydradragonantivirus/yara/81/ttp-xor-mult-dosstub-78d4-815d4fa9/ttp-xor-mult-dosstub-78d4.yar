rule TTP_XOR_MULT_DOSStub_78d4 {
  strings:
    $key_78d4 = { 2c bc [2] 58 a4 [2] 1f a6 [2] 58 b7 [2] 16 bb [2] 1a b1 [2] 0d ba [2] 16 f4 [2] 2b }

  condition:
    any of them
}