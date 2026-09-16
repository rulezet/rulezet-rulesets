rule TTP_XOR_MULT_DOSStub_4cd8 {
  strings:
    $key_4cd8 = { 18 b0 [2] 6c a8 [2] 2b aa [2] 6c bb [2] 22 b7 [2] 2e bd [2] 39 b6 [2] 22 f8 [2] 1f }

  condition:
    any of them
}