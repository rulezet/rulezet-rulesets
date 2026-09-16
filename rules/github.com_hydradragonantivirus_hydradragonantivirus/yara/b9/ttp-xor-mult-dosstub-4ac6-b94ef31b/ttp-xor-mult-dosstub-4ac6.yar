rule TTP_XOR_MULT_DOSStub_4ac6 {
  strings:
    $key_4ac6 = { 1e ae [2] 6a b6 [2] 2d b4 [2] 6a a5 [2] 24 a9 [2] 28 a3 [2] 3f a8 [2] 24 e6 [2] 19 }

  condition:
    any of them
}