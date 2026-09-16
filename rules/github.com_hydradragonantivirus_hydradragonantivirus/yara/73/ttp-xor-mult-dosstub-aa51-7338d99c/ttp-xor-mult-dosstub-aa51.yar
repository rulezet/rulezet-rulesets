rule TTP_XOR_MULT_DOSStub_aa51 {
  strings:
    $key_aa51 = { fe 39 [2] 8a 21 [2] cd 23 [2] 8a 32 [2] c4 3e [2] c8 34 [2] df 3f [2] c4 71 [2] f9 }

  condition:
    any of them
}