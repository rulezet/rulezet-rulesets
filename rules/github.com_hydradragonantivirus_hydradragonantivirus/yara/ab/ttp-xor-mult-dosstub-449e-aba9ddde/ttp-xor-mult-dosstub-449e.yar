rule TTP_XOR_MULT_DOSStub_449e {
  strings:
    $key_449e = { 10 f6 [2] 64 ee [2] 23 ec [2] 64 fd [2] 2a f1 [2] 26 fb [2] 31 f0 [2] 2a be [2] 17 }

  condition:
    any of them
}