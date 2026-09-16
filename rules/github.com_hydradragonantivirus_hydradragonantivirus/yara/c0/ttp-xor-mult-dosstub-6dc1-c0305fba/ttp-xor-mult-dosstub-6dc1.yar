rule TTP_XOR_MULT_DOSStub_6dc1 {
  strings:
    $key_6dc1 = { 39 a9 [2] 4d b1 [2] 0a b3 [2] 4d a2 [2] 03 ae [2] 0f a4 [2] 18 af [2] 03 e1 [2] 3e }

  condition:
    any of them
}