rule TTP_XOR_MULT_DOSStub_aa22 {
  strings:
    $key_aa22 = { fe 4a [2] 8a 52 [2] cd 50 [2] 8a 41 [2] c4 4d [2] c8 47 [2] df 4c [2] c4 02 [2] f9 }

  condition:
    any of them
}