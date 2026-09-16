rule TTP_XOR_MULT_DOSStub_e2c3 {
  strings:
    $key_e2c3 = { b6 ab [2] c2 b3 [2] 85 b1 [2] c2 a0 [2] 8c ac [2] 80 a6 [2] 97 ad [2] 8c e3 [2] b1 }

  condition:
    any of them
}