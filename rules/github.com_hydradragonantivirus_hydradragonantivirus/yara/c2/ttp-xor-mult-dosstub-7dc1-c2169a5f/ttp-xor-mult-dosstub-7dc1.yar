rule TTP_XOR_MULT_DOSStub_7dc1 {
  strings:
    $key_7dc1 = { 29 a9 [2] 5d b1 [2] 1a b3 [2] 5d a2 [2] 13 ae [2] 1f a4 [2] 08 af [2] 13 e1 [2] 2e }

  condition:
    any of them
}