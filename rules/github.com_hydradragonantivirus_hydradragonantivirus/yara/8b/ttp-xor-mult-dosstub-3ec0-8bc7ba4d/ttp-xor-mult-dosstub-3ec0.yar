rule TTP_XOR_MULT_DOSStub_3ec0 {
  strings:
    $key_3ec0 = { 6a a8 [2] 1e b0 [2] 59 b2 [2] 1e a3 [2] 50 af [2] 5c a5 [2] 4b ae [2] 50 e0 [2] 6d }

  condition:
    any of them
}