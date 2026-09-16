rule TTP_XOR_MULT_DOSStub_5c9e {
  strings:
    $key_5c9e = { 08 f6 [2] 7c ee [2] 3b ec [2] 7c fd [2] 32 f1 [2] 3e fb [2] 29 f0 [2] 32 be [2] 0f }

  condition:
    any of them
}