rule TTP_XOR_MULT_DOSStub_e2c5 {
  strings:
    $key_e2c5 = { b6 ad [2] c2 b5 [2] 85 b7 [2] c2 a6 [2] 8c aa [2] 80 a0 [2] 97 ab [2] 8c e5 [2] b1 }

  condition:
    any of them
}