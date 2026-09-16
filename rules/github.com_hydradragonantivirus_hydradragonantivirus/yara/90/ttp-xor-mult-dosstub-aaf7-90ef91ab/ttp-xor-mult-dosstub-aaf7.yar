rule TTP_XOR_MULT_DOSStub_aaf7 {
  strings:
    $key_aaf7 = { fe 9f [2] 8a 87 [2] cd 85 [2] 8a 94 [2] c4 98 [2] c8 92 [2] df 99 [2] c4 d7 [2] f9 }

  condition:
    any of them
}