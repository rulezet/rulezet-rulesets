rule TTP_XOR_MULT_DOSStub_aa65 {
  strings:
    $key_aa65 = { fe 0d [2] 8a 15 [2] cd 17 [2] 8a 06 [2] c4 0a [2] c8 00 [2] df 0b [2] c4 45 [2] f9 }

  condition:
    any of them
}