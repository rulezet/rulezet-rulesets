rule TTP_XOR_MULT_DOSStub_afac {
  strings:
    $key_afac = { fb c4 [2] 8f dc [2] c8 de [2] 8f cf [2] c1 c3 [2] cd c9 [2] da c2 [2] c1 8c [2] fc }

  condition:
    any of them
}