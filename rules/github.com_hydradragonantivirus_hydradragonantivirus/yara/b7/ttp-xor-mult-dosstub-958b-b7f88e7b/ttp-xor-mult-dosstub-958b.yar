rule TTP_XOR_MULT_DOSStub_958b {
  strings:
    $key_958b = { c1 e3 [2] b5 fb [2] f2 f9 [2] b5 e8 [2] fb e4 [2] f7 ee [2] e0 e5 [2] fb ab [2] c6 }

  condition:
    any of them
}