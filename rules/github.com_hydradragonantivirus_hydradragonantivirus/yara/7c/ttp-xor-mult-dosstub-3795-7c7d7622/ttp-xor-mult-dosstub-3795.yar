rule TTP_XOR_MULT_DOSStub_3795 {
  strings:
    $key_3795 = { 63 fd [2] 17 e5 [2] 50 e7 [2] 17 f6 [2] 59 fa [2] 55 f0 [2] 42 fb [2] 59 b5 [2] 64 }

  condition:
    any of them
}