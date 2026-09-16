rule TTP_XOR_MULT_DOSStub_aa40 {
  strings:
    $key_aa40 = { fe 28 [2] 8a 30 [2] cd 32 [2] 8a 23 [2] c4 2f [2] c8 25 [2] df 2e [2] c4 60 [2] f9 }

  condition:
    any of them
}