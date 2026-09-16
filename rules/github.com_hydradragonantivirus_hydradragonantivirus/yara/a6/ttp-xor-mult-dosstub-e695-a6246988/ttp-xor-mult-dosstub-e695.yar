rule TTP_XOR_MULT_DOSStub_e695 {
  strings:
    $key_e695 = { b2 fd [2] c6 e5 [2] 81 e7 [2] c6 f6 [2] 88 fa [2] 84 f0 [2] 93 fb [2] 88 b5 [2] b5 }

  condition:
    any of them
}