rule TTP_XOR_MULT_DOSStub_42d6 {
  strings:
    $key_42d6 = { 16 be [2] 62 a6 [2] 25 a4 [2] 62 b5 [2] 2c b9 [2] 20 b3 [2] 37 b8 [2] 2c f6 [2] 11 }

  condition:
    any of them
}