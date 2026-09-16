rule TTP_XOR_MULT_DOSStub_79c4 {
  strings:
    $key_79c4 = { 2d ac [2] 59 b4 [2] 1e b6 [2] 59 a7 [2] 17 ab [2] 1b a1 [2] 0c aa [2] 17 e4 [2] 2a }

  condition:
    any of them
}