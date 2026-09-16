rule TTP_XOR_MULT_DOSStub_49c0 {
  strings:
    $key_49c0 = { 1d a8 [2] 69 b0 [2] 2e b2 [2] 69 a3 [2] 27 af [2] 2b a5 [2] 3c ae [2] 27 e0 [2] 1a }

  condition:
    any of them
}