rule TTP_XOR_MULT_DOSStub_78d8 {
  strings:
    $key_78d8 = { 2c b0 [2] 58 a8 [2] 1f aa [2] 58 bb [2] 16 b7 [2] 1a bd [2] 0d b6 [2] 16 f8 [2] 2b }

  condition:
    any of them
}