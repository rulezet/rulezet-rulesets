rule TTP_XOR_MULT_DOSStub_59c4 {
  strings:
    $key_59c4 = { 0d ac [2] 79 b4 [2] 3e b6 [2] 79 a7 [2] 37 ab [2] 3b a1 [2] 2c aa [2] 37 e4 [2] 0a }

  condition:
    any of them
}