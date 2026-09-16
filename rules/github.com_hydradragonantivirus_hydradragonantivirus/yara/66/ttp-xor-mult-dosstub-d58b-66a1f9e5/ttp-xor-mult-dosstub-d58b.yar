rule TTP_XOR_MULT_DOSStub_d58b {
  strings:
    $key_d58b = { 81 e3 [2] f5 fb [2] b2 f9 [2] f5 e8 [2] bb e4 [2] b7 ee [2] a0 e5 [2] bb ab [2] 86 }

  condition:
    any of them
}