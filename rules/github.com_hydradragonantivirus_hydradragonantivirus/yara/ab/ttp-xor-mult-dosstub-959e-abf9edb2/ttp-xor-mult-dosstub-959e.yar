rule TTP_XOR_MULT_DOSStub_959e {
  strings:
    $key_959e = { c1 f6 [2] b5 ee [2] f2 ec [2] b5 fd [2] fb f1 [2] f7 fb [2] e0 f0 [2] fb be [2] c6 }

  condition:
    any of them
}