rule TTP_XOR_MULT_DOSStub_6dd8 {
  strings:
    $key_6dd8 = { 39 b0 [2] 4d a8 [2] 0a aa [2] 4d bb [2] 03 b7 [2] 0f bd [2] 18 b6 [2] 03 f8 [2] 3e }

  condition:
    any of them
}