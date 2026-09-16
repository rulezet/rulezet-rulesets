rule TTP_XOR_MULT_DOSStub_6f9e {
  strings:
    $key_6f9e = { 3b f6 [2] 4f ee [2] 08 ec [2] 4f fd [2] 01 f1 [2] 0d fb [2] 1a f0 [2] 01 be [2] 3c }

  condition:
    any of them
}