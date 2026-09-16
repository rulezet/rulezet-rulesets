rule TTP_XOR_MULT_DOSStub_aae5 {
  strings:
    $key_aae5 = { fe 8d [2] 8a 95 [2] cd 97 [2] 8a 86 [2] c4 8a [2] c8 80 [2] df 8b [2] c4 c5 [2] f9 }

  condition:
    any of them
}