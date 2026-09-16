rule TTP_XOR_MULT_DOSStub_aa29 {
  strings:
    $key_aa29 = { fe 41 [2] 8a 59 [2] cd 5b [2] 8a 4a [2] c4 46 [2] c8 4c [2] df 47 [2] c4 09 [2] f9 }

  condition:
    any of them
}