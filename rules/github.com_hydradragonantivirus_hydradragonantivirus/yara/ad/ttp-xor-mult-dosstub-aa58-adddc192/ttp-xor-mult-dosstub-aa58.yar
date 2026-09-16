rule TTP_XOR_MULT_DOSStub_aa58 {
  strings:
    $key_aa58 = { fe 30 [2] 8a 28 [2] cd 2a [2] 8a 3b [2] c4 37 [2] c8 3d [2] df 36 [2] c4 78 [2] f9 }

  condition:
    any of them
}