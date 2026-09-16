rule TTP_XOR_MULT_DOSStub_affa {
  strings:
    $key_affa = { fb 92 [2] 8f 8a [2] c8 88 [2] 8f 99 [2] c1 95 [2] cd 9f [2] da 94 [2] c1 da [2] fc }

  condition:
    any of them
}