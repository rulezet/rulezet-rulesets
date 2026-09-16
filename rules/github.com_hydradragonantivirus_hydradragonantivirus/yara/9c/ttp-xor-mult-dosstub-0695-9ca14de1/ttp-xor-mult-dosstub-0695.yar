rule TTP_XOR_MULT_DOSStub_0695 {
  strings:
    $key_0695 = { 52 fd [2] 26 e5 [2] 61 e7 [2] 26 f6 [2] 68 fa [2] 64 f0 [2] 73 fb [2] 68 b5 [2] 55 }

  condition:
    any of them
}