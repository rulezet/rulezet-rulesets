rule TTP_XOR_MULT_DOSStub_aa4d {
  strings:
    $key_aa4d = { fe 25 [2] 8a 3d [2] cd 3f [2] 8a 2e [2] c4 22 [2] c8 28 [2] df 23 [2] c4 6d [2] f9 }

  condition:
    any of them
}