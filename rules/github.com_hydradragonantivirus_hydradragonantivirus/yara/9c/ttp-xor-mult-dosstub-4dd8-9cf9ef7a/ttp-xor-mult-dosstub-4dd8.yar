rule TTP_XOR_MULT_DOSStub_4dd8 {
  strings:
    $key_4dd8 = { 19 b0 [2] 6d a8 [2] 2a aa [2] 6d bb [2] 23 b7 [2] 2f bd [2] 38 b6 [2] 23 f8 [2] 1e }

  condition:
    any of them
}