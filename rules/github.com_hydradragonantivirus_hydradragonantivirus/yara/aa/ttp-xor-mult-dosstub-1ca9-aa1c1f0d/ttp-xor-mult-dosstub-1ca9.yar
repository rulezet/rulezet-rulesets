rule TTP_XOR_MULT_DOSStub_1ca9 {
  strings:
    $key_1ca9 = { 48 c1 [2] 3c d9 [2] 7b db [2] 3c ca [2] 72 c6 [2] 7e cc [2] 69 c7 [2] 72 89 [2] 4f }

  condition:
    any of them
}