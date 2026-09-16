rule TTP_XOR_MULT_DOSStub_559e {
  strings:
    $key_559e = { 01 f6 [2] 75 ee [2] 32 ec [2] 75 fd [2] 3b f1 [2] 37 fb [2] 20 f0 [2] 3b be [2] 06 }

  condition:
    any of them
}