rule TTP_XOR_MULT_DOSStub_0cd8 {
  strings:
    $key_0cd8 = { 58 b0 [2] 2c a8 [2] 6b aa [2] 2c bb [2] 62 b7 [2] 6e bd [2] 79 b6 [2] 62 f8 [2] 5f }

  condition:
    any of them
}