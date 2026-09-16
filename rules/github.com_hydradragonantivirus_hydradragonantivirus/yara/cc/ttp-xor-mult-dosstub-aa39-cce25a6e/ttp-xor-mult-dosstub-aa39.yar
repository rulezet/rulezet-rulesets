rule TTP_XOR_MULT_DOSStub_aa39 {
  strings:
    $key_aa39 = { fe 51 [2] 8a 49 [2] cd 4b [2] 8a 5a [2] c4 56 [2] c8 5c [2] df 57 [2] c4 19 [2] f9 }

  condition:
    any of them
}