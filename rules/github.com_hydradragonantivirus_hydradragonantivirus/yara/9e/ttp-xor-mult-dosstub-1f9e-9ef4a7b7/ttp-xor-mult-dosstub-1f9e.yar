rule TTP_XOR_MULT_DOSStub_1f9e {
  strings:
    $key_1f9e = { 4b f6 [2] 3f ee [2] 78 ec [2] 3f fd [2] 71 f1 [2] 7d fb [2] 6a f0 [2] 71 be [2] 4c }

  condition:
    any of them
}