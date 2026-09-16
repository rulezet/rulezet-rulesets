rule TTP_XOR_MULT_DOSStub_c795 {
  strings:
    $key_c795 = { 93 fd [2] e7 e5 [2] a0 e7 [2] e7 f6 [2] a9 fa [2] a5 f0 [2] b2 fb [2] a9 b5 [2] 94 }

  condition:
    any of them
}