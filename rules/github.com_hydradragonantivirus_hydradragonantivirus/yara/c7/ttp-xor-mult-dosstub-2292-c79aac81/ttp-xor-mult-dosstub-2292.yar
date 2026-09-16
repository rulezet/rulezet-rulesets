rule TTP_XOR_MULT_DOSStub_2292 {
  strings:
    $key_2292 = { 76 fa [2] 02 e2 [2] 45 e0 [2] 02 f1 [2] 4c fd [2] 40 f7 [2] 57 fc [2] 4c b2 [2] 71 }

  condition:
    any of them
}