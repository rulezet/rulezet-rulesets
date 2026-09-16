rule TTP_XOR_MULT_DOSStub_389e {
  strings:
    $key_389e = { 6c f6 [2] 18 ee [2] 5f ec [2] 18 fd [2] 56 f1 [2] 5a fb [2] 4d f0 [2] 56 be [2] 6b }

  condition:
    any of them
}