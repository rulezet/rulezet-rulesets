rule TTP_XOR_MULT_DOSStub_a79e {
  strings:
    $key_a79e = { f3 f6 [2] 87 ee [2] c0 ec [2] 87 fd [2] c9 f1 [2] c5 fb [2] d2 f0 [2] c9 be [2] f4 }

  condition:
    any of them
}