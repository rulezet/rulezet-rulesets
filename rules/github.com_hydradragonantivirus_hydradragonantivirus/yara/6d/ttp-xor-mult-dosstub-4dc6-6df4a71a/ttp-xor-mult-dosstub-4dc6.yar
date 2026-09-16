rule TTP_XOR_MULT_DOSStub_4dc6 {
  strings:
    $key_4dc6 = { 19 ae [2] 6d b6 [2] 2a b4 [2] 6d a5 [2] 23 a9 [2] 2f a3 [2] 38 a8 [2] 23 e6 [2] 1e }

  condition:
    any of them
}