rule TTP_XOR_MULT_DOSStub_aa56 {
  strings:
    $key_aa56 = { fe 3e [2] 8a 26 [2] cd 24 [2] 8a 35 [2] c4 39 [2] c8 33 [2] df 38 [2] c4 76 [2] f9 }

  condition:
    any of them
}