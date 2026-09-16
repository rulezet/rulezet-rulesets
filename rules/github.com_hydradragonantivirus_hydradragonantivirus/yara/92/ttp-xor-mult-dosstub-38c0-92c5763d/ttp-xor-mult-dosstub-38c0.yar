rule TTP_XOR_MULT_DOSStub_38c0 {
  strings:
    $key_38c0 = { 6c a8 [2] 18 b0 [2] 5f b2 [2] 18 a3 [2] 56 af [2] 5a a5 [2] 4d ae [2] 56 e0 [2] 6b }

  condition:
    any of them
}