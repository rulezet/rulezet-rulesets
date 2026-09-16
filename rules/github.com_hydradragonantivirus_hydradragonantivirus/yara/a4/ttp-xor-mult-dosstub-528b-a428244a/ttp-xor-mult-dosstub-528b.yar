rule TTP_XOR_MULT_DOSStub_528b {
  strings:
    $key_528b = { 06 e3 [2] 72 fb [2] 35 f9 [2] 72 e8 [2] 3c e4 [2] 30 ee [2] 27 e5 [2] 3c ab [2] 01 }

  condition:
    any of them
}