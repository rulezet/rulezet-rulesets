rule TTP_XOR_MULT_DOSStub_42c1 {
  strings:
    $key_42c1 = { 16 a9 [2] 62 b1 [2] 25 b3 [2] 62 a2 [2] 2c ae [2] 20 a4 [2] 37 af [2] 2c e1 [2] 11 }

  condition:
    any of them
}