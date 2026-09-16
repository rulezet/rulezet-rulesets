rule TTP_XOR_MULT_DOSStub_708b {
  strings:
    $key_708b = { 24 e3 [2] 50 fb [2] 17 f9 [2] 50 e8 [2] 1e e4 [2] 12 ee [2] 05 e5 [2] 1e ab [2] 23 }

  condition:
    any of them
}