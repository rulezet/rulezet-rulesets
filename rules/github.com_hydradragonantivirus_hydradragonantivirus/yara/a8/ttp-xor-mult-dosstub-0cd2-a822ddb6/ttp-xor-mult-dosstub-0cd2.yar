rule TTP_XOR_MULT_DOSStub_0cd2 {
  strings:
    $key_0cd2 = { 58 ba [2] 2c a2 [2] 6b a0 [2] 2c b1 [2] 62 bd [2] 6e b7 [2] 79 bc [2] 62 f2 [2] 5f }

  condition:
    any of them
}