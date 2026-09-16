rule TTP_XOR_MULT_DOSStub_0cd3 {
  strings:
    $key_0cd3 = { 58 bb [2] 2c a3 [2] 6b a1 [2] 2c b0 [2] 62 bc [2] 6e b6 [2] 79 bd [2] 62 f3 [2] 5f }

  condition:
    any of them
}