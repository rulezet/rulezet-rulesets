rule TTP_XOR_MULT_DOSStub_c19e {
  strings:
    $key_c19e = { 95 f6 [2] e1 ee [2] a6 ec [2] e1 fd [2] af f1 [2] a3 fb [2] b4 f0 [2] af be [2] 92 }

  condition:
    any of them
}