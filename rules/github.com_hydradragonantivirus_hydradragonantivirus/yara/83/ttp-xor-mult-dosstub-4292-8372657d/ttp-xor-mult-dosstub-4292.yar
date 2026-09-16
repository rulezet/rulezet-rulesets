rule TTP_XOR_MULT_DOSStub_4292 {
  strings:
    $key_4292 = { 16 fa [2] 62 e2 [2] 25 e0 [2] 62 f1 [2] 2c fd [2] 20 f7 [2] 37 fc [2] 2c b2 [2] 11 }

  condition:
    any of them
}