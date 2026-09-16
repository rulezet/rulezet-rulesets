rule TTP_XOR_MULT_DOSStub_3794 {
  strings:
    $key_3794 = { 63 fc [2] 17 e4 [2] 50 e6 [2] 17 f7 [2] 59 fb [2] 55 f1 [2] 42 fa [2] 59 b4 [2] 64 }

  condition:
    any of them
}