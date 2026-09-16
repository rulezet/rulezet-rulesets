rule TTP_XOR_MULT_DOSStub_afd7 {
  strings:
    $key_afd7 = { fb bf [2] 8f a7 [2] c8 a5 [2] 8f b4 [2] c1 b8 [2] cd b2 [2] da b9 [2] c1 f7 [2] fc }

  condition:
    any of them
}