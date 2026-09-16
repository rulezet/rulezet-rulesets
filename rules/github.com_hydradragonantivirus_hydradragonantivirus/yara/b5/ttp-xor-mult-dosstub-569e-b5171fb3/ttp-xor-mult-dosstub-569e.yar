rule TTP_XOR_MULT_DOSStub_569e {
  strings:
    $key_569e = { 02 f6 [2] 76 ee [2] 31 ec [2] 76 fd [2] 38 f1 [2] 34 fb [2] 23 f0 [2] 38 be [2] 05 }

  condition:
    any of them
}