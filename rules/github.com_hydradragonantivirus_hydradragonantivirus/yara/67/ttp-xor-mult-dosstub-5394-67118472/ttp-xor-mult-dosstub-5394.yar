rule TTP_XOR_MULT_DOSStub_5394 {
  strings:
    $key_5394 = { 07 fc [2] 73 e4 [2] 34 e6 [2] 73 f7 [2] 3d fb [2] 31 f1 [2] 26 fa [2] 3d b4 [2] 00 }

  condition:
    any of them
}