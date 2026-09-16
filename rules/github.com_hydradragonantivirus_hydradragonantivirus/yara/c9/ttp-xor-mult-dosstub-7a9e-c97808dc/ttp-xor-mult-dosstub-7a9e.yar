rule TTP_XOR_MULT_DOSStub_7a9e {
  strings:
    $key_7a9e = { 2e f6 [2] 5a ee [2] 1d ec [2] 5a fd [2] 14 f1 [2] 18 fb [2] 0f f0 [2] 14 be [2] 29 }

  condition:
    any of them
}