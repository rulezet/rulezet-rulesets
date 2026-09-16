rule TTP_XOR_MULT_DOSStub_4f9e {
  strings:
    $key_4f9e = { 1b f6 [2] 6f ee [2] 28 ec [2] 6f fd [2] 21 f1 [2] 2d fb [2] 3a f0 [2] 21 be [2] 1c }

  condition:
    any of them
}