rule TTP_XOR_MULT_DOSStub_9793 {
  strings:
    $key_9793 = { c3 fb [2] b7 e3 [2] f0 e1 [2] b7 f0 [2] f9 fc [2] f5 f6 [2] e2 fd [2] f9 b3 [2] c4 }

  condition:
    any of them
}