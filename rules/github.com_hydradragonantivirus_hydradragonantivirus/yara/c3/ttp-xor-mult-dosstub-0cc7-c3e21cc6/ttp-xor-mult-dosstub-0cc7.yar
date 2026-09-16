rule TTP_XOR_MULT_DOSStub_0cc7 {
  strings:
    $key_0cc7 = { 58 af [2] 2c b7 [2] 6b b5 [2] 2c a4 [2] 62 a8 [2] 6e a2 [2] 79 a9 [2] 62 e7 [2] 5f }

  condition:
    any of them
}