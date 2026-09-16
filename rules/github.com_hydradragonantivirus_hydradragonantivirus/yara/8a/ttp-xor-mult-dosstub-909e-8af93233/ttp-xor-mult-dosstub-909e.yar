rule TTP_XOR_MULT_DOSStub_909e {
  strings:
    $key_909e = { c4 f6 [2] b0 ee [2] f7 ec [2] b0 fd [2] fe f1 [2] f2 fb [2] e5 f0 [2] fe be [2] c3 }

  condition:
    any of them
}