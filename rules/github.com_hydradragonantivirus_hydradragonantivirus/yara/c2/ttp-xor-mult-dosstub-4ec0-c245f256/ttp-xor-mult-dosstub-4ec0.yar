rule TTP_XOR_MULT_DOSStub_4ec0 {
  strings:
    $key_4ec0 = { 1a a8 [2] 6e b0 [2] 29 b2 [2] 6e a3 [2] 20 af [2] 2c a5 [2] 3b ae [2] 20 e0 [2] 1d }

  condition:
    any of them
}