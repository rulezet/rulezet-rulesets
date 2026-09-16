rule TTP_XOR_MULT_DOSStub_aa2e {
  strings:
    $key_aa2e = { fe 46 [2] 8a 5e [2] cd 5c [2] 8a 4d [2] c4 41 [2] c8 4b [2] df 40 [2] c4 0e [2] f9 }

  condition:
    any of them
}