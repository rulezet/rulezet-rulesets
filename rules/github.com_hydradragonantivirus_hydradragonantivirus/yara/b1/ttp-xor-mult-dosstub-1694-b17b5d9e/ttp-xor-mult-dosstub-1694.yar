rule TTP_XOR_MULT_DOSStub_1694 {
  strings:
    $key_1694 = { 42 fc [2] 36 e4 [2] 71 e6 [2] 36 f7 [2] 78 fb [2] 74 f1 [2] 63 fa [2] 78 b4 [2] 45 }

  condition:
    any of them
}