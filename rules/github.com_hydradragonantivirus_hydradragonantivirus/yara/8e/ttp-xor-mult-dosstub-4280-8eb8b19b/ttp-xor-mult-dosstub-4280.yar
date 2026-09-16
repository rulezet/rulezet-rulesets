rule TTP_XOR_MULT_DOSStub_4280 {
  strings:
    $key_4280 = { 16 e8 [2] 62 f0 [2] 25 f2 [2] 62 e3 [2] 2c ef [2] 20 e5 [2] 37 ee [2] 2c a0 [2] 11 }

  condition:
    any of them
}