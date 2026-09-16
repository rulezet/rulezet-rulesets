rule TTP_XOR_MULT_DOSStub_79c0 {
  strings:
    $key_79c0 = { 2d a8 [2] 59 b0 [2] 1e b2 [2] 59 a3 [2] 17 af [2] 1b a5 [2] 0c ae [2] 17 e0 [2] 2a }

  condition:
    any of them
}