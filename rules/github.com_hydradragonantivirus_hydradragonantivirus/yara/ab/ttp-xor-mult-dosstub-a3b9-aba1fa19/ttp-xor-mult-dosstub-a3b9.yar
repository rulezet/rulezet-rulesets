rule TTP_XOR_MULT_DOSStub_a3b9 {
  strings:
    $key_a3b9 = { f7 d1 [2] 83 c9 [2] c4 cb [2] 83 da [2] cd d6 [2] c1 dc [2] d6 d7 [2] cd 99 [2] f0 }

  condition:
    any of them
}