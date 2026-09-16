rule TTP_XOR_MULT_DOSStub_7292 {
  strings:
    $key_7292 = { 26 fa [2] 52 e2 [2] 15 e0 [2] 52 f1 [2] 1c fd [2] 10 f7 [2] 07 fc [2] 1c b2 [2] 21 }

  condition:
    any of them
}