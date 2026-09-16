rule TTP_XOR_MULT_DOSStub_1794 {
  strings:
    $key_1794 = { 43 fc [2] 37 e4 [2] 70 e6 [2] 37 f7 [2] 79 fb [2] 75 f1 [2] 62 fa [2] 79 b4 [2] 44 }

  condition:
    any of them
}