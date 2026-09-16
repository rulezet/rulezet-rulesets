rule TTP_XOR_MULT_DOSStub_aa03 {
  strings:
    $key_aa03 = { fe 6b [2] 8a 73 [2] cd 71 [2] 8a 60 [2] c4 6c [2] c8 66 [2] df 6d [2] c4 23 [2] f9 }

  condition:
    any of them
}