rule TTP_XOR_MULT_DOSStub_aaa1 {
  strings:
    $key_aaa1 = { fe c9 [2] 8a d1 [2] cd d3 [2] 8a c2 [2] c4 ce [2] c8 c4 [2] df cf [2] c4 81 [2] f9 }

  condition:
    any of them
}