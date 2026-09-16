rule TTP_XOR_MULT_DOSStub_42d1 {
  strings:
    $key_42d1 = { 16 b9 [2] 62 a1 [2] 25 a3 [2] 62 b2 [2] 2c be [2] 20 b4 [2] 37 bf [2] 2c f1 [2] 11 }

  condition:
    any of them
}