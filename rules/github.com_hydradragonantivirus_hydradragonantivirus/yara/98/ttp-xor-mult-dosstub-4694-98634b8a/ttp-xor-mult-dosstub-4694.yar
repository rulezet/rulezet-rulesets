rule TTP_XOR_MULT_DOSStub_4694 {
  strings:
    $key_4694 = { 12 fc [2] 66 e4 [2] 21 e6 [2] 66 f7 [2] 28 fb [2] 24 f1 [2] 33 fa [2] 28 b4 [2] 15 }

  condition:
    any of them
}