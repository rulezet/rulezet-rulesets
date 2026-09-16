rule TTP_XOR_MULT_DOSStub_aac1 {
  strings:
    $key_aac1 = { fe a9 [2] 8a b1 [2] cd b3 [2] 8a a2 [2] c4 ae [2] c8 a4 [2] df af [2] c4 e1 [2] f9 }

  condition:
    any of them
}