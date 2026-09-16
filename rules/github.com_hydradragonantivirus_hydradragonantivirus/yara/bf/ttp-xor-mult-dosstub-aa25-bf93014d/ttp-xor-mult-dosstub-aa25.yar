rule TTP_XOR_MULT_DOSStub_aa25 {
  strings:
    $key_aa25 = { fe 4d [2] 8a 55 [2] cd 57 [2] 8a 46 [2] c4 4a [2] c8 40 [2] df 4b [2] c4 05 [2] f9 }

  condition:
    any of them
}