rule TTP_XOR_MULT_DOSStub_aa1d {
  strings:
    $key_aa1d = { fe 75 [2] 8a 6d [2] cd 6f [2] 8a 7e [2] c4 72 [2] c8 78 [2] df 73 [2] c4 3d [2] f9 }

  condition:
    any of them
}