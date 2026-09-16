rule TTP_XOR_MULT_DOSStub_aa62 {
  strings:
    $key_aa62 = { fe 0a [2] 8a 12 [2] cd 10 [2] 8a 01 [2] c4 0d [2] c8 07 [2] df 0c [2] c4 42 [2] f9 }

  condition:
    any of them
}