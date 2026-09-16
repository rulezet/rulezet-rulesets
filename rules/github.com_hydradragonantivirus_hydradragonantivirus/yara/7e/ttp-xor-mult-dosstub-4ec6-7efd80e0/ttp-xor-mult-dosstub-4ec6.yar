rule TTP_XOR_MULT_DOSStub_4ec6 {
  strings:
    $key_4ec6 = { 1a ae [2] 6e b6 [2] 29 b4 [2] 6e a5 [2] 20 a9 [2] 2c a3 [2] 3b a8 [2] 20 e6 [2] 1d }

  condition:
    any of them
}