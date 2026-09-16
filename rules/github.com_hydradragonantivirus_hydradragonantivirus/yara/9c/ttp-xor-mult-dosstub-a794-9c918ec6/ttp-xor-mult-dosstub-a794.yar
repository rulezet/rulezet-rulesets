rule TTP_XOR_MULT_DOSStub_a794 {
  strings:
    $key_a794 = { f3 fc [2] 87 e4 [2] c0 e6 [2] 87 f7 [2] c9 fb [2] c5 f1 [2] d2 fa [2] c9 b4 [2] f4 }

  condition:
    any of them
}