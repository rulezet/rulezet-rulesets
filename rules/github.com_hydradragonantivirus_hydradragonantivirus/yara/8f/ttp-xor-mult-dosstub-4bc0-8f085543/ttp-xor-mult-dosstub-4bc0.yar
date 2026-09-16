rule TTP_XOR_MULT_DOSStub_4bc0 {
  strings:
    $key_4bc0 = { 1f a8 [2] 6b b0 [2] 2c b2 [2] 6b a3 [2] 25 af [2] 29 a5 [2] 3e ae [2] 25 e0 [2] 18 }

  condition:
    any of them
}