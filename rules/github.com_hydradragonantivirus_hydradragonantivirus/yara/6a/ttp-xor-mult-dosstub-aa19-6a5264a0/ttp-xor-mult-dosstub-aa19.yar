rule TTP_XOR_MULT_DOSStub_aa19 {
  strings:
    $key_aa19 = { fe 71 [2] 8a 69 [2] cd 6b [2] 8a 7a [2] c4 76 [2] c8 7c [2] df 77 [2] c4 39 [2] f9 }

  condition:
    any of them
}