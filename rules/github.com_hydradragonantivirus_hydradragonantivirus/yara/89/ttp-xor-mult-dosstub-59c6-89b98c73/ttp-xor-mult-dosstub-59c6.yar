rule TTP_XOR_MULT_DOSStub_59c6 {
  strings:
    $key_59c6 = { 0d ae [2] 79 b6 [2] 3e b4 [2] 79 a5 [2] 37 a9 [2] 3b a3 [2] 2c a8 [2] 37 e6 [2] 0a }

  condition:
    any of them
}