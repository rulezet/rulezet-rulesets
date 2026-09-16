rule TTP_XOR_MULT_DOSStub_aa24 {
  strings:
    $key_aa24 = { fe 4c [2] 8a 54 [2] cd 56 [2] 8a 47 [2] c4 4b [2] c8 41 [2] df 4a [2] c4 04 [2] f9 }

  condition:
    any of them
}