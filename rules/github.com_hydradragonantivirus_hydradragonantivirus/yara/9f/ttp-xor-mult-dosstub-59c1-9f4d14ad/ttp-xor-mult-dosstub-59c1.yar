rule TTP_XOR_MULT_DOSStub_59c1 {
  strings:
    $key_59c1 = { 0d a9 [2] 79 b1 [2] 3e b3 [2] 79 a2 [2] 37 ae [2] 3b a4 [2] 2c af [2] 37 e1 [2] 0a }

  condition:
    any of them
}