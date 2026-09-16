rule TTP_XOR_MULT_DOSStub_169e {
  strings:
    $key_169e = { 42 f6 [2] 36 ee [2] 71 ec [2] 36 fd [2] 78 f1 [2] 74 fb [2] 63 f0 [2] 78 be [2] 45 }

  condition:
    any of them
}