rule TTP_XOR_MULT_DOSStub_afb4 {
  strings:
    $key_afb4 = { fb dc [2] 8f c4 [2] c8 c6 [2] 8f d7 [2] c1 db [2] cd d1 [2] da da [2] c1 94 [2] fc }

  condition:
    any of them
}