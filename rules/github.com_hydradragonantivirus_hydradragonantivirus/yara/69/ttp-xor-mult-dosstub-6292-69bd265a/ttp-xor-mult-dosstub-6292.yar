rule TTP_XOR_MULT_DOSStub_6292 {
  strings:
    $key_6292 = { 36 fa [2] 42 e2 [2] 05 e0 [2] 42 f1 [2] 0c fd [2] 00 f7 [2] 17 fc [2] 0c b2 [2] 31 }

  condition:
    any of them
}