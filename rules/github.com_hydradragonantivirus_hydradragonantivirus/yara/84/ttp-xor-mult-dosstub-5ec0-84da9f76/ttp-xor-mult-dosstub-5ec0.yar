rule TTP_XOR_MULT_DOSStub_5ec0 {
  strings:
    $key_5ec0 = { 0a a8 [2] 7e b0 [2] 39 b2 [2] 7e a3 [2] 30 af [2] 3c a5 [2] 2b ae [2] 30 e0 [2] 0d }

  condition:
    any of them
}