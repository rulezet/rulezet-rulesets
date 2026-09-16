rule TTP_XOR_MULT_DOSStub_aad1 {
  strings:
    $key_aad1 = { fe b9 [2] 8a a1 [2] cd a3 [2] 8a b2 [2] c4 be [2] c8 b4 [2] df bf [2] c4 f1 [2] f9 }

  condition:
    any of them
}