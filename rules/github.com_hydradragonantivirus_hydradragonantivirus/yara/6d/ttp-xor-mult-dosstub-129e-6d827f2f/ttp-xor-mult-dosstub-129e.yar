rule TTP_XOR_MULT_DOSStub_129e {
  strings:
    $key_129e = { 46 f6 [2] 32 ee [2] 75 ec [2] 32 fd [2] 7c f1 [2] 70 fb [2] 67 f0 [2] 7c be [2] 41 }

  condition:
    any of them
}