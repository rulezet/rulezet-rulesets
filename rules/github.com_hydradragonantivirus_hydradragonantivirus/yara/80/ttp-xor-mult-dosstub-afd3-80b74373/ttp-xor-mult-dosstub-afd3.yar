rule TTP_XOR_MULT_DOSStub_afd3 {
  strings:
    $key_afd3 = { fb bb [2] 8f a3 [2] c8 a1 [2] 8f b0 [2] c1 bc [2] cd b6 [2] da bd [2] c1 f3 [2] fc }

  condition:
    any of them
}