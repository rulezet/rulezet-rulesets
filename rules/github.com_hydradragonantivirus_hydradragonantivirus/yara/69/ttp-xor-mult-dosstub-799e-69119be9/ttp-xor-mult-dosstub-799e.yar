rule TTP_XOR_MULT_DOSStub_799e {
  strings:
    $key_799e = { 2d f6 [2] 59 ee [2] 1e ec [2] 59 fd [2] 17 f1 [2] 1b fb [2] 0c f0 [2] 17 be [2] 2a }

  condition:
    any of them
}