rule TTP_XOR_MULT_DOSStub_aa34 {
  strings:
    $key_aa34 = { fe 5c [2] 8a 44 [2] cd 46 [2] 8a 57 [2] c4 5b [2] c8 51 [2] df 5a [2] c4 14 [2] f9 }

  condition:
    any of them
}