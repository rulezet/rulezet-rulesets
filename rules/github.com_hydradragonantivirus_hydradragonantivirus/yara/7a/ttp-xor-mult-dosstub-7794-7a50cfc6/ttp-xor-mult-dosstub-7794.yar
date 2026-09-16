rule TTP_XOR_MULT_DOSStub_7794 {
  strings:
    $key_7794 = { 23 fc [2] 57 e4 [2] 10 e6 [2] 57 f7 [2] 19 fb [2] 15 f1 [2] 02 fa [2] 19 b4 [2] 24 }

  condition:
    any of them
}