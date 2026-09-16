rule TTP_XOR_MULT_DOSStub_3ca9 {
  strings:
    $key_3ca9 = { 68 c1 [2] 1c d9 [2] 5b db [2] 1c ca [2] 52 c6 [2] 5e cc [2] 49 c7 [2] 52 89 [2] 6f }

  condition:
    any of them
}