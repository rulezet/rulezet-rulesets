rule TTP_XOR_MULT_DOSStub_4ca9 {
  strings:
    $key_4ca9 = { 18 c1 [2] 6c d9 [2] 2b db [2] 6c ca [2] 22 c6 [2] 2e cc [2] 39 c7 [2] 22 89 [2] 1f }

  condition:
    any of them
}