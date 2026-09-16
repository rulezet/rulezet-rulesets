rule TTP_XOR_MULT_DOSStub_1494 {
  strings:
    $key_1494 = { 40 fc [2] 34 e4 [2] 73 e6 [2] 34 f7 [2] 7a fb [2] 76 f1 [2] 61 fa [2] 7a b4 [2] 47 }

  condition:
    any of them
}