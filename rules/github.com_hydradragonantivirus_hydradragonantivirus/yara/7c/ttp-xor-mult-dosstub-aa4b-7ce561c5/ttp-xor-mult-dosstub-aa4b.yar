rule TTP_XOR_MULT_DOSStub_aa4b {
  strings:
    $key_aa4b = { fe 23 [2] 8a 3b [2] cd 39 [2] 8a 28 [2] c4 24 [2] c8 2e [2] df 25 [2] c4 6b [2] f9 }

  condition:
    any of them
}