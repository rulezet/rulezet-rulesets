rule TTP_XOR_MULT_DOSStub_c29e {
  strings:
    $key_c29e = { 96 f6 [2] e2 ee [2] a5 ec [2] e2 fd [2] ac f1 [2] a0 fb [2] b7 f0 [2] ac be [2] 91 }

  condition:
    any of them
}