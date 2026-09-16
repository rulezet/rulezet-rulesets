rule TTP_XOR_MULT_DOSStub_5292 {
  strings:
    $key_5292 = { 06 fa [2] 72 e2 [2] 35 e0 [2] 72 f1 [2] 3c fd [2] 30 f7 [2] 27 fc [2] 3c b2 [2] 01 }

  condition:
    any of them
}