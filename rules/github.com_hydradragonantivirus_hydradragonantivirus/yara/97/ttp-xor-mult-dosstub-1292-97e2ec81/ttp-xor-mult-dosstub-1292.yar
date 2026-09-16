rule TTP_XOR_MULT_DOSStub_1292 {
  strings:
    $key_1292 = { 46 fa [2] 32 e2 [2] 75 e0 [2] 32 f1 [2] 7c fd [2] 70 f7 [2] 67 fc [2] 7c b2 [2] 41 }

  condition:
    any of them
}