rule TTP_XOR_MULT_DOSStub_49c4 {
  strings:
    $key_49c4 = { 1d ac [2] 69 b4 [2] 2e b6 [2] 69 a7 [2] 27 ab [2] 2b a1 [2] 3c aa [2] 27 e4 [2] 1a }

  condition:
    any of them
}