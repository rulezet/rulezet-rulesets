rule TTP_XOR_MULT_DOSStub_3a9e {
  strings:
    $key_3a9e = { 6e f6 [2] 1a ee [2] 5d ec [2] 1a fd [2] 54 f1 [2] 58 fb [2] 4f f0 [2] 54 be [2] 69 }

  condition:
    any of them
}