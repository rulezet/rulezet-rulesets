rule TTP_XOR_MULT_DOSStub_aa75 {
  strings:
    $key_aa75 = { fe 1d [2] 8a 05 [2] cd 07 [2] 8a 16 [2] c4 1a [2] c8 10 [2] df 1b [2] c4 55 [2] f9 }

  condition:
    any of them
}