rule TTP_XOR_MULT_DOSStub_049e {
  strings:
    $key_049e = { 50 f6 [2] 24 ee [2] 63 ec [2] 24 fd [2] 6a f1 [2] 66 fb [2] 71 f0 [2] 6a be [2] 57 }

  condition:
    any of them
}