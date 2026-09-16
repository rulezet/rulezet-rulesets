rule TTP_XOR_MULT_DOSStub_e98b {
  strings:
    $key_e98b = { bd e3 [2] c9 fb [2] 8e f9 [2] c9 e8 [2] 87 e4 [2] 8b ee [2] 9c e5 [2] 87 ab [2] ba }

  condition:
    any of them
}