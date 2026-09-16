rule TTP_XOR_MULT_DOSStub_2cd8 {
  strings:
    $key_2cd8 = { 78 b0 [2] 0c a8 [2] 4b aa [2] 0c bb [2] 42 b7 [2] 4e bd [2] 59 b6 [2] 42 f8 [2] 7f }

  condition:
    any of them
}