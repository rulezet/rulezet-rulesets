rule TTP_XOR_MULT_DOSStub_a39e {
  strings:
    $key_a39e = { f7 f6 [2] 83 ee [2] c4 ec [2] 83 fd [2] cd f1 [2] c1 fb [2] d6 f0 [2] cd be [2] f0 }

  condition:
    any of them
}