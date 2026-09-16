rule TTP_XOR_MULT_DOSStub_e2c6 {
  strings:
    $key_e2c6 = { b6 ae [2] c2 b6 [2] 85 b4 [2] c2 a5 [2] 8c a9 [2] 80 a3 [2] 97 a8 [2] 8c e6 [2] b1 }

  condition:
    any of them
}