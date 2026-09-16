rule TTP_XOR_MULT_DOSStub_49c6 {
  strings:
    $key_49c6 = { 1d ae [2] 69 b6 [2] 2e b4 [2] 69 a5 [2] 27 a9 [2] 2b a3 [2] 3c a8 [2] 27 e6 [2] 1a }

  condition:
    any of them
}