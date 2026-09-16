rule TTP_XOR_MULT_DOSStub_228b {
  strings:
    $key_228b = { 76 e3 [2] 02 fb [2] 45 f9 [2] 02 e8 [2] 4c e4 [2] 40 ee [2] 57 e5 [2] 4c ab [2] 71 }

  condition:
    any of them
}