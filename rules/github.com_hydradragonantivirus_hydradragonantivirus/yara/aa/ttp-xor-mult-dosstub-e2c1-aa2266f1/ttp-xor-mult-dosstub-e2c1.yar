rule TTP_XOR_MULT_DOSStub_e2c1 {
  strings:
    $key_e2c1 = { b6 a9 [2] c2 b1 [2] 85 b3 [2] c2 a2 [2] 8c ae [2] 80 a4 [2] 97 af [2] 8c e1 [2] b1 }

  condition:
    any of them
}