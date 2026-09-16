rule TTP_XOR_MULT_DOSStub_2794 {
  strings:
    $key_2794 = { 73 fc [2] 07 e4 [2] 40 e6 [2] 07 f7 [2] 49 fb [2] 45 f1 [2] 52 fa [2] 49 b4 [2] 74 }

  condition:
    any of them
}