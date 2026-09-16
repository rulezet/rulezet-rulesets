rule TTP_XOR_MULT_DOSStub_598b {
  strings:
    $key_598b = { 0d e3 [2] 79 fb [2] 3e f9 [2] 79 e8 [2] 37 e4 [2] 3b ee [2] 2c e5 [2] 37 ab [2] 0a }

  condition:
    any of them
}