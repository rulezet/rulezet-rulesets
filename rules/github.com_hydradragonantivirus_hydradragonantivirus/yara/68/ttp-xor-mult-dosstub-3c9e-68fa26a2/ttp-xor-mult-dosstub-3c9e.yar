rule TTP_XOR_MULT_DOSStub_3c9e {
  strings:
    $key_3c9e = { 68 f6 [2] 1c ee [2] 5b ec [2] 1c fd [2] 52 f1 [2] 5e fb [2] 49 f0 [2] 52 be [2] 6f }

  condition:
    any of them
}