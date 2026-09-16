rule TTP_XOR_MULT_DOSStub_afb5 {
  strings:
    $key_afb5 = { fb dd [2] 8f c5 [2] c8 c7 [2] 8f d6 [2] c1 da [2] cd d0 [2] da db [2] c1 95 [2] fc }

  condition:
    any of them
}