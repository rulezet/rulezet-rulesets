rule TTP_XOR_MULT_DOSStub_aa55 {
  strings:
    $key_aa55 = { fe 3d [2] 8a 25 [2] cd 27 [2] 8a 36 [2] c4 3a [2] c8 30 [2] df 3b [2] c4 75 [2] f9 }

  condition:
    any of them
}