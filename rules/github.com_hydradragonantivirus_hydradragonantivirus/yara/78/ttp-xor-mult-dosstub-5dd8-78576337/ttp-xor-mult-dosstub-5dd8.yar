rule TTP_XOR_MULT_DOSStub_5dd8 {
  strings:
    $key_5dd8 = { 09 b0 [2] 7d a8 [2] 3a aa [2] 7d bb [2] 33 b7 [2] 3f bd [2] 28 b6 [2] 33 f8 [2] 0e }

  condition:
    any of them
}