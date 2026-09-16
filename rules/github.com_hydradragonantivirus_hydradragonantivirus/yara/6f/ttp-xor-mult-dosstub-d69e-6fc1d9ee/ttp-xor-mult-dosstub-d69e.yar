rule TTP_XOR_MULT_DOSStub_d69e {
  strings:
    $key_d69e = { 82 f6 [2] f6 ee [2] b1 ec [2] f6 fd [2] b8 f1 [2] b4 fb [2] a3 f0 [2] b8 be [2] 85 }

  condition:
    any of them
}