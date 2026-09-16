rule TTP_XOR_MULT_DOSStub_42d9 {
  strings:
    $key_42d9 = { 16 b1 [2] 62 a9 [2] 25 ab [2] 62 ba [2] 2c b6 [2] 20 bc [2] 37 b7 [2] 2c f9 [2] 11 }

  condition:
    any of them
}