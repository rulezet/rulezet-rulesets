rule TTP_XOR_MULT_DOSStub_af89 {
  strings:
    $key_af89 = { fb e1 [2] 8f f9 [2] c8 fb [2] 8f ea [2] c1 e6 [2] cd ec [2] da e7 [2] c1 a9 [2] fc }

  condition:
    any of them
}