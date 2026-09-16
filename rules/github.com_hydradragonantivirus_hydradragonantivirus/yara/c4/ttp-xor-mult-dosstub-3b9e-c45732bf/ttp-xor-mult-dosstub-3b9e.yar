rule TTP_XOR_MULT_DOSStub_3b9e {
  strings:
    $key_3b9e = { 6f f6 [2] 1b ee [2] 5c ec [2] 1b fd [2] 55 f1 [2] 59 fb [2] 4e f0 [2] 55 be [2] 68 }

  condition:
    any of them
}