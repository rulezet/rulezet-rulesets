rule TTP_XOR_MULT_DOSStub_aa57 {
  strings:
    $key_aa57 = { fe 3f [2] 8a 27 [2] cd 25 [2] 8a 34 [2] c4 38 [2] c8 32 [2] df 39 [2] c4 77 [2] f9 }

  condition:
    any of them
}