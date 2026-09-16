rule TTP_XOR_MULT_DOSStub_42c3 {
  strings:
    $key_42c3 = { 16 ab [2] 62 b3 [2] 25 b1 [2] 62 a0 [2] 2c ac [2] 20 a6 [2] 37 ad [2] 2c e3 [2] 11 }

  condition:
    any of them
}