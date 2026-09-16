rule TTP_XOR_MULT_DOSStub_7ca9 {
  strings:
    $key_7ca9 = { 28 c1 [2] 5c d9 [2] 1b db [2] 5c ca [2] 12 c6 [2] 1e cc [2] 09 c7 [2] 12 89 [2] 2f }

  condition:
    any of them
}