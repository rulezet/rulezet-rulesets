rule TTP_XOR_MULT_DOSStub_4296 {
  strings:
    $key_4296 = { 16 fe [2] 62 e6 [2] 25 e4 [2] 62 f5 [2] 2c f9 [2] 20 f3 [2] 37 f8 [2] 2c b6 [2] 11 }

  condition:
    any of them
}