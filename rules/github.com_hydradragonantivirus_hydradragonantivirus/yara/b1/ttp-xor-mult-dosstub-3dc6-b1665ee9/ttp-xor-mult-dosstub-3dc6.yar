rule TTP_XOR_MULT_DOSStub_3dc6 {
  strings:
    $key_3dc6 = { 69 ae [2] 1d b6 [2] 5a b4 [2] 1d a5 [2] 53 a9 [2] 5f a3 [2] 48 a8 [2] 53 e6 [2] 6e }

  condition:
    any of them
}