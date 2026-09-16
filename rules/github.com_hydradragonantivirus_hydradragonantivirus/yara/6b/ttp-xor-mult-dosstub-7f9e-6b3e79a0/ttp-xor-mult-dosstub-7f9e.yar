rule TTP_XOR_MULT_DOSStub_7f9e {
  strings:
    $key_7f9e = { 2b f6 [2] 5f ee [2] 18 ec [2] 5f fd [2] 11 f1 [2] 1d fb [2] 0a f0 [2] 11 be [2] 2c }

  condition:
    any of them
}