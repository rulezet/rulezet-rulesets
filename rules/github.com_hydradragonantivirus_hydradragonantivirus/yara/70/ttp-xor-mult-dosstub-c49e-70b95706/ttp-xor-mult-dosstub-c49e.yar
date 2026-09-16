rule TTP_XOR_MULT_DOSStub_c49e {
  strings:
    $key_c49e = { 90 f6 [2] e4 ee [2] a3 ec [2] e4 fd [2] aa f1 [2] a6 fb [2] b1 f0 [2] aa be [2] 97 }

  condition:
    any of them
}