rule TTP_XOR_MULT_DOSStub_4290 {
  strings:
    $key_4290 = { 16 f8 [2] 62 e0 [2] 25 e2 [2] 62 f3 [2] 2c ff [2] 20 f5 [2] 37 fe [2] 2c b0 [2] 11 }

  condition:
    any of them
}