rule TTP_XOR_MULT_DOSStub_0cc0 {
  strings:
    $key_0cc0 = { 58 a8 [2] 2c b0 [2] 6b b2 [2] 2c a3 [2] 62 af [2] 6e a5 [2] 79 ae [2] 62 e0 [2] 5f }

  condition:
    any of them
}