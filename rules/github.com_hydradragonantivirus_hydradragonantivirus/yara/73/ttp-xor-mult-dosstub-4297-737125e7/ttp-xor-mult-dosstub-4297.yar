rule TTP_XOR_MULT_DOSStub_4297 {
  strings:
    $key_4297 = { 16 ff [2] 62 e7 [2] 25 e5 [2] 62 f4 [2] 2c f8 [2] 20 f2 [2] 37 f9 [2] 2c b7 [2] 11 }

  condition:
    any of them
}