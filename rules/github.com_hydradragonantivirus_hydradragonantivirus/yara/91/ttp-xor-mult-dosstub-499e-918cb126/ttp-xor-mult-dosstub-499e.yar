rule TTP_XOR_MULT_DOSStub_499e {
  strings:
    $key_499e = { 1d f6 [2] 69 ee [2] 2e ec [2] 69 fd [2] 27 f1 [2] 2b fb [2] 3c f0 [2] 27 be [2] 1a }

  condition:
    any of them
}