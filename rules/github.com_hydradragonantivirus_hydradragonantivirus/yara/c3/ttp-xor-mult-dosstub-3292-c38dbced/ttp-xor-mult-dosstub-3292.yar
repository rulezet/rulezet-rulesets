rule TTP_XOR_MULT_DOSStub_3292 {
  strings:
    $key_3292 = { 66 fa [2] 12 e2 [2] 55 e0 [2] 12 f1 [2] 5c fd [2] 50 f7 [2] 47 fc [2] 5c b2 [2] 61 }

  condition:
    any of them
}