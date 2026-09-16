rule TTP_XOR_MULT_DOSStub_5694 {
  strings:
    $key_5694 = { 02 fc [2] 76 e4 [2] 31 e6 [2] 76 f7 [2] 38 fb [2] 34 f1 [2] 23 fa [2] 38 b4 [2] 05 }

  condition:
    any of them
}