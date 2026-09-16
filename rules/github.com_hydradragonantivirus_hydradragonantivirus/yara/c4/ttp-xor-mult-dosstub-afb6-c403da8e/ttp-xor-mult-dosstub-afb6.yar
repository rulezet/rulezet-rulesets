rule TTP_XOR_MULT_DOSStub_afb6 {
  strings:
    $key_afb6 = { fb de [2] 8f c6 [2] c8 c4 [2] 8f d5 [2] c1 d9 [2] cd d3 [2] da d8 [2] c1 96 [2] fc }

  condition:
    any of them
}