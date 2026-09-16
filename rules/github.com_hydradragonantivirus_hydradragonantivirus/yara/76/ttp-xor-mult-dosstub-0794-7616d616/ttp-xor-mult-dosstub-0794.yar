rule TTP_XOR_MULT_DOSStub_0794 {
  strings:
    $key_0794 = { 53 fc [2] 27 e4 [2] 60 e6 [2] 27 f7 [2] 69 fb [2] 65 f1 [2] 72 fa [2] 69 b4 [2] 54 }

  condition:
    any of them
}