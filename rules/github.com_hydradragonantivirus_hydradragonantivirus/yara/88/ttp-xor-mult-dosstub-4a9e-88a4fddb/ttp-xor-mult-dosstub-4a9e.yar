rule TTP_XOR_MULT_DOSStub_4a9e {
  strings:
    $key_4a9e = { 1e f6 [2] 6a ee [2] 2d ec [2] 6a fd [2] 24 f1 [2] 28 fb [2] 3f f0 [2] 24 be [2] 19 }

  condition:
    any of them
}