rule TTP_XOR_MULT_DOSStub_58d8 {
  strings:
    $key_58d8 = { 0c b0 [2] 78 a8 [2] 3f aa [2] 78 bb [2] 36 b7 [2] 3a bd [2] 2d b6 [2] 36 f8 [2] 0b }

  condition:
    any of them
}