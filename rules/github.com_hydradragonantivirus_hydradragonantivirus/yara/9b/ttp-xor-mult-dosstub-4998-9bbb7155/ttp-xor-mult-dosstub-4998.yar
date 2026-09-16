rule TTP_XOR_MULT_DOSStub_4998 {
  strings:
    $key_4998 = { 1d f0 [2] 69 e8 [2] 2e ea [2] 69 fb [2] 27 f7 [2] 2b fd [2] 3c f6 [2] 27 b8 [2] 1a }

  condition:
    any of them
}