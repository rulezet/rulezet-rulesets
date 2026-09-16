rule TTP_XOR_MULT_DOSStub_aa14 {
  strings:
    $key_aa14 = { fe 7c [2] 8a 64 [2] cd 66 [2] 8a 77 [2] c4 7b [2] c8 71 [2] df 7a [2] c4 34 [2] f9 }

  condition:
    any of them
}