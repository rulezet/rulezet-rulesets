rule TTP_XOR_MULT_DOSStub_e09e {
  strings:
    $key_e09e = { b4 f6 [2] c0 ee [2] 87 ec [2] c0 fd [2] 8e f1 [2] 82 fb [2] 95 f0 [2] 8e be [2] b3 }

  condition:
    any of them
}