rule TTP_XOR_MULT_DOSStub_8695 {
  strings:
    $key_8695 = { d2 fd [2] a6 e5 [2] e1 e7 [2] a6 f6 [2] e8 fa [2] e4 f0 [2] f3 fb [2] e8 b5 [2] d5 }

  condition:
    any of them
}