rule TTP_XOR_MULT_DOSStub_78d2 {
  strings:
    $key_78d2 = { 2c ba [2] 58 a2 [2] 1f a0 [2] 58 b1 [2] 16 bd [2] 1a b7 [2] 0d bc [2] 16 f2 [2] 2b }

  condition:
    any of them
}