rule TTP_XOR_MULT_DOSStub_869e {
  strings:
    $key_869e = { d2 f6 [2] a6 ee [2] e1 ec [2] a6 fd [2] e8 f1 [2] e4 fb [2] f3 f0 [2] e8 be [2] d5 }

  condition:
    any of them
}