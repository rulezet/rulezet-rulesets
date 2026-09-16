rule TTP_XOR_MULT_DOSStub_5f9e {
  strings:
    $key_5f9e = { 0b f6 [2] 7f ee [2] 38 ec [2] 7f fd [2] 31 f1 [2] 3d fb [2] 2a f0 [2] 31 be [2] 0c }

  condition:
    any of them
}