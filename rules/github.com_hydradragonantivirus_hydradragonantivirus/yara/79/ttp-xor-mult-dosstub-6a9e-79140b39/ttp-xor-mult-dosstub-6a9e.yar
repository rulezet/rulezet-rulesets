rule TTP_XOR_MULT_DOSStub_6a9e {
  strings:
    $key_6a9e = { 3e f6 [2] 4a ee [2] 0d ec [2] 4a fd [2] 04 f1 [2] 08 fb [2] 1f f0 [2] 04 be [2] 39 }

  condition:
    any of them
}