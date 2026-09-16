rule TTP_XOR_MULT_DOSStub_409e {
  strings:
    $key_409e = { 14 f6 [2] 60 ee [2] 27 ec [2] 60 fd [2] 2e f1 [2] 22 fb [2] 35 f0 [2] 2e be [2] 13 }

  condition:
    any of them
}