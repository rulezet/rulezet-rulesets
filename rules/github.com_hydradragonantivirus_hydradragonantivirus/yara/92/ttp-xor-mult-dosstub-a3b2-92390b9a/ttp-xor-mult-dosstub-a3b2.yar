rule TTP_XOR_MULT_DOSStub_a3b2 {
  strings:
    $key_a3b2 = { f7 da [2] 83 c2 [2] c4 c0 [2] 83 d1 [2] cd dd [2] c1 d7 [2] d6 dc [2] cd 92 [2] f0 }

  condition:
    any of them
}