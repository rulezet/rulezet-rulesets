rule TTP_XOR_MULT_DOSStub_da9e {
  strings:
    $key_da9e = { 8e f6 [2] fa ee [2] bd ec [2] fa fd [2] b4 f1 [2] b8 fb [2] af f0 [2] b4 be [2] 89 }

  condition:
    any of them
}