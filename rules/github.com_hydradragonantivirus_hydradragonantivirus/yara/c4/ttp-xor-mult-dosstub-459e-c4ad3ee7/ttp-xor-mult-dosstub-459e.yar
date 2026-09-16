rule TTP_XOR_MULT_DOSStub_459e {
  strings:
    $key_459e = { 11 f6 [2] 65 ee [2] 22 ec [2] 65 fd [2] 2b f1 [2] 27 fb [2] 30 f0 [2] 2b be [2] 16 }

  condition:
    any of them
}