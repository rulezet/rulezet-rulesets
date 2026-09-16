rule TTP_XOR_MULT_DOSStub_209e {
  strings:
    $key_209e = { 74 f6 [2] 00 ee [2] 47 ec [2] 00 fd [2] 4e f1 [2] 42 fb [2] 55 f0 [2] 4e be [2] 73 }

  condition:
    any of them
}