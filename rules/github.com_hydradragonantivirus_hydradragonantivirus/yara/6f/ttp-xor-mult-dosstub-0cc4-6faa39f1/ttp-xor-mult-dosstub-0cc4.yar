rule TTP_XOR_MULT_DOSStub_0cc4 {
  strings:
    $key_0cc4 = { 58 ac [2] 2c b4 [2] 6b b6 [2] 2c a7 [2] 62 ab [2] 6e a1 [2] 79 aa [2] 62 e4 [2] 5f }

  condition:
    any of them
}