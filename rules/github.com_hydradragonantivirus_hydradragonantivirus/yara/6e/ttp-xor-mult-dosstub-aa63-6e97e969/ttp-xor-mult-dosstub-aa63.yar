rule TTP_XOR_MULT_DOSStub_aa63 {
  strings:
    $key_aa63 = { fe 0b [2] 8a 13 [2] cd 11 [2] 8a 00 [2] c4 0c [2] c8 06 [2] df 0d [2] c4 43 [2] f9 }

  condition:
    any of them
}