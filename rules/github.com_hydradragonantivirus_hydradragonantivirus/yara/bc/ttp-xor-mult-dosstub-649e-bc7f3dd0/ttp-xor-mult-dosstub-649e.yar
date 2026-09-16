rule TTP_XOR_MULT_DOSStub_649e {
  strings:
    $key_649e = { 30 f6 [2] 44 ee [2] 03 ec [2] 44 fd [2] 0a f1 [2] 06 fb [2] 11 f0 [2] 0a be [2] 37 }

  condition:
    any of them
}