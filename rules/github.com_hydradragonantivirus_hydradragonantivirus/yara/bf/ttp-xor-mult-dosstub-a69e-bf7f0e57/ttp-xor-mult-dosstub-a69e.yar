rule TTP_XOR_MULT_DOSStub_a69e {
  strings:
    $key_a69e = { f2 f6 [2] 86 ee [2] c1 ec [2] 86 fd [2] c8 f1 [2] c4 fb [2] d3 f0 [2] c8 be [2] f5 }

  condition:
    any of them
}