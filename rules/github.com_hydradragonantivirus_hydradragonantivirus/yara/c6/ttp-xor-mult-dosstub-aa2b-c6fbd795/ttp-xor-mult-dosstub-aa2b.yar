rule TTP_XOR_MULT_DOSStub_aa2b {
  strings:
    $key_aa2b = { fe 43 [2] 8a 5b [2] cd 59 [2] 8a 48 [2] c4 44 [2] c8 4e [2] df 45 [2] c4 0b [2] f9 }

  condition:
    any of them
}