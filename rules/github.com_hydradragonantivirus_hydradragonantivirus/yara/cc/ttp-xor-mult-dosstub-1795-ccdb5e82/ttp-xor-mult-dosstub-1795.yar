rule TTP_XOR_MULT_DOSStub_1795 {
  strings:
    $key_1795 = { 43 fd [2] 37 e5 [2] 70 e7 [2] 37 f6 [2] 79 fa [2] 75 f0 [2] 62 fb [2] 79 b5 [2] 44 }

  condition:
    any of them
}