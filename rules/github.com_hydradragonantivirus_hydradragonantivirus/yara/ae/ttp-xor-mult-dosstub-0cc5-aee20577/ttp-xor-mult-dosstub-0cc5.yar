rule TTP_XOR_MULT_DOSStub_0cc5 {
  strings:
    $key_0cc5 = { 58 ad [2] 2c b5 [2] 6b b7 [2] 2c a6 [2] 62 aa [2] 6e a0 [2] 79 ab [2] 62 e5 [2] 5f }

  condition:
    any of them
}