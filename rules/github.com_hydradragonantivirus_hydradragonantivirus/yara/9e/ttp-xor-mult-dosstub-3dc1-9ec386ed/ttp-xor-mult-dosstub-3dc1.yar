rule TTP_XOR_MULT_DOSStub_3dc1 {
  strings:
    $key_3dc1 = { 69 a9 [2] 1d b1 [2] 5a b3 [2] 1d a2 [2] 53 ae [2] 5f a4 [2] 48 af [2] 53 e1 [2] 6e }

  condition:
    any of them
}