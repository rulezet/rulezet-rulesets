rule TTP_XOR_MULT_DOSStub_af8b {
  strings:
    $key_af8b = { fb e3 [2] 8f fb [2] c8 f9 [2] 8f e8 [2] c1 e4 [2] cd ee [2] da e5 [2] c1 ab [2] fc }

  condition:
    any of them
}