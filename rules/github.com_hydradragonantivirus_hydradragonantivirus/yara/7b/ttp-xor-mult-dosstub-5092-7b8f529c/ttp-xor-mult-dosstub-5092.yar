rule TTP_XOR_MULT_DOSStub_5092 {
  strings:
    $key_5092 = { 04 fa [2] 70 e2 [2] 37 e0 [2] 70 f1 [2] 3e fd [2] 32 f7 [2] 25 fc [2] 3e b2 [2] 03 }

  condition:
    any of them
}