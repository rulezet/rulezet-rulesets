rule TTP_XOR_MULT_DOSStub_aaa7 {
  strings:
    $key_aaa7 = { fe cf [2] 8a d7 [2] cd d5 [2] 8a c4 [2] c4 c8 [2] c8 c2 [2] df c9 [2] c4 87 [2] f9 }

  condition:
    any of them
}