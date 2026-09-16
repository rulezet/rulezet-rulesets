rule TTP_XOR_MULT_DOSStub_e2c0 {
  strings:
    $key_e2c0 = { b6 a8 [2] c2 b0 [2] 85 b2 [2] c2 a3 [2] 8c af [2] 80 a5 [2] 97 ae [2] 8c e0 [2] b1 }

  condition:
    any of them
}