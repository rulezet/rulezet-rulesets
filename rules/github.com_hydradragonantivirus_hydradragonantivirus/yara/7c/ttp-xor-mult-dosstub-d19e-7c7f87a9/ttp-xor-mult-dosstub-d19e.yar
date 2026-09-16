rule TTP_XOR_MULT_DOSStub_d19e {
  strings:
    $key_d19e = { 85 f6 [2] f1 ee [2] b6 ec [2] f1 fd [2] bf f1 [2] b3 fb [2] a4 f0 [2] bf be [2] 82 }

  condition:
    any of them
}