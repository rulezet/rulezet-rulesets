rule TTP_XOR_MULT_DOSStub_aa5d {
  strings:
    $key_aa5d = { fe 35 [2] 8a 2d [2] cd 2f [2] 8a 3e [2] c4 32 [2] c8 38 [2] df 33 [2] c4 7d [2] f9 }

  condition:
    any of them
}