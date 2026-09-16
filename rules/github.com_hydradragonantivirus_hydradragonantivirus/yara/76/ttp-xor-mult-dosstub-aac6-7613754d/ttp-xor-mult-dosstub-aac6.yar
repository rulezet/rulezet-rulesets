rule TTP_XOR_MULT_DOSStub_aac6 {
  strings:
    $key_aac6 = { fe ae [2] 8a b6 [2] cd b4 [2] 8a a5 [2] c4 a9 [2] c8 a3 [2] df a8 [2] c4 e6 [2] f9 }

  condition:
    any of them
}