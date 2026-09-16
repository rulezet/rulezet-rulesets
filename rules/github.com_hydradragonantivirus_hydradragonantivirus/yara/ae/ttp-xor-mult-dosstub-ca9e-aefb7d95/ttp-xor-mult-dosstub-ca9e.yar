rule TTP_XOR_MULT_DOSStub_ca9e {
  strings:
    $key_ca9e = { 9e f6 [2] ea ee [2] ad ec [2] ea fd [2] a4 f1 [2] a8 fb [2] bf f0 [2] a4 be [2] 99 }

  condition:
    any of them
}