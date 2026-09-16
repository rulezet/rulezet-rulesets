rule TTP_XOR_MULT_DOSStub_7dc0 {
  strings:
    $key_7dc0 = { 29 a8 [2] 5d b0 [2] 1a b2 [2] 5d a3 [2] 13 af [2] 1f a5 [2] 08 ae [2] 13 e0 [2] 2e }

  condition:
    any of them
}