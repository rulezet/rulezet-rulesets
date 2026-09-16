rule TTP_XOR_MULT_DOSStub_4286 {
  strings:
    $key_4286 = { 16 ee [2] 62 f6 [2] 25 f4 [2] 62 e5 [2] 2c e9 [2] 20 e3 [2] 37 e8 [2] 2c a6 [2] 11 }

  condition:
    any of them
}