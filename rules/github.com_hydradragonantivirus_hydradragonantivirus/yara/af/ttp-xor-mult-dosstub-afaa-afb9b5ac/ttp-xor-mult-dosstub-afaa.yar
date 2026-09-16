rule TTP_XOR_MULT_DOSStub_afaa {
  strings:
    $key_afaa = { fb c2 [2] 8f da [2] c8 d8 [2] 8f c9 [2] c1 c5 [2] cd cf [2] da c4 [2] c1 8a [2] fc }

  condition:
    any of them
}