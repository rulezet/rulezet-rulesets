rule TTP_XOR_MULT_DOSStub_afb3 {
  strings:
    $key_afb3 = { fb db [2] 8f c3 [2] c8 c1 [2] 8f d0 [2] c1 dc [2] cd d6 [2] da dd [2] c1 93 [2] fc }

  condition:
    any of them
}