rule TTP_XOR_MULT_DOSStub_afa7 {
  strings:
    $key_afa7 = { fb cf [2] 8f d7 [2] c8 d5 [2] 8f c4 [2] c1 c8 [2] cd c2 [2] da c9 [2] c1 87 [2] fc }

  condition:
    any of them
}