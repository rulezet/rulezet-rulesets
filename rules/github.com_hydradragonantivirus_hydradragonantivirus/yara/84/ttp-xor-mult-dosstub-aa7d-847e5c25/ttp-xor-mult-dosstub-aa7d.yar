rule TTP_XOR_MULT_DOSStub_aa7d {
  strings:
    $key_aa7d = { fe 15 [2] 8a 0d [2] cd 0f [2] 8a 1e [2] c4 12 [2] c8 18 [2] df 13 [2] c4 5d [2] f9 }

  condition:
    any of them
}