rule TTP_XOR_MULT_DOSStub_aab3 {
  strings:
    $key_aab3 = { fe db [2] 8a c3 [2] cd c1 [2] 8a d0 [2] c4 dc [2] c8 d6 [2] df dd [2] c4 93 [2] f9 }

  condition:
    any of them
}