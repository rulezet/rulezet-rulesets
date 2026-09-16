rule TTP_XOR_MULT_DOSStub_4c9e {
  strings:
    $key_4c9e = { 18 f6 [2] 6c ee [2] 2b ec [2] 6c fd [2] 22 f1 [2] 2e fb [2] 39 f0 [2] 22 be [2] 1f }

  condition:
    any of them
}