rule TTP_XOR_MULT_DOSStub_0a9e {
  strings:
    $key_0a9e = { 5e f6 [2] 2a ee [2] 6d ec [2] 2a fd [2] 64 f1 [2] 68 fb [2] 7f f0 [2] 64 be [2] 59 }

  condition:
    any of them
}