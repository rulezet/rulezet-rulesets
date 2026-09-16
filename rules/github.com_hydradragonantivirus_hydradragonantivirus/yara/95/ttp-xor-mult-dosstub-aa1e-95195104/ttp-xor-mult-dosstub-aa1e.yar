rule TTP_XOR_MULT_DOSStub_aa1e {
  strings:
    $key_aa1e = { fe 76 [2] 8a 6e [2] cd 6c [2] 8a 7d [2] c4 71 [2] c8 7b [2] df 70 [2] c4 3e [2] f9 }

  condition:
    any of them
}