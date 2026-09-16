rule TTP_XOR_MULT_DOSStub_338b {
  strings:
    $key_338b = { 67 e3 [2] 13 fb [2] 54 f9 [2] 13 e8 [2] 5d e4 [2] 51 ee [2] 46 e5 [2] 5d ab [2] 60 }

  condition:
    any of them
}