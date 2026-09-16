rule TTP_XOR_MULT_DOSStub_aa6d {
  strings:
    $key_aa6d = { fe 05 [2] 8a 1d [2] cd 1f [2] 8a 0e [2] c4 02 [2] c8 08 [2] df 03 [2] c4 4d [2] f9 }

  condition:
    any of them
}