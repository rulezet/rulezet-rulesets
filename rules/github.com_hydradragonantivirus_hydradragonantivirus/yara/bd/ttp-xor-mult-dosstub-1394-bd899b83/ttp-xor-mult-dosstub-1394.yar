rule TTP_XOR_MULT_DOSStub_1394 {
  strings:
    $key_1394 = { 47 fc [2] 33 e4 [2] 74 e6 [2] 33 f7 [2] 7d fb [2] 71 f1 [2] 66 fa [2] 7d b4 [2] 40 }

  condition:
    any of them
}