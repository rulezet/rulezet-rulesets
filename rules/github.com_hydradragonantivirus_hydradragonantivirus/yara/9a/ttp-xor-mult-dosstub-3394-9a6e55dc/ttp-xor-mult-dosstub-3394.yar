rule TTP_XOR_MULT_DOSStub_3394 {
  strings:
    $key_3394 = { 67 fc [2] 13 e4 [2] 54 e6 [2] 13 f7 [2] 5d fb [2] 51 f1 [2] 46 fa [2] 5d b4 [2] 60 }

  condition:
    any of them
}