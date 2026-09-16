rule TTP_XOR_MULT_DOSStub_5ca9 {
  strings:
    $key_5ca9 = { 08 c1 [2] 7c d9 [2] 3b db [2] 7c ca [2] 32 c6 [2] 3e cc [2] 29 c7 [2] 32 89 [2] 0f }

  condition:
    any of them
}