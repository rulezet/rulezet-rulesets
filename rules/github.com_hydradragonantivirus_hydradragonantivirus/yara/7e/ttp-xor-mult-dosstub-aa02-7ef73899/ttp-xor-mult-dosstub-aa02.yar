rule TTP_XOR_MULT_DOSStub_aa02 {
  strings:
    $key_aa02 = { fe 6a [2] 8a 72 [2] cd 70 [2] 8a 61 [2] c4 6d [2] c8 67 [2] df 6c [2] c4 22 [2] f9 }

  condition:
    any of them
}