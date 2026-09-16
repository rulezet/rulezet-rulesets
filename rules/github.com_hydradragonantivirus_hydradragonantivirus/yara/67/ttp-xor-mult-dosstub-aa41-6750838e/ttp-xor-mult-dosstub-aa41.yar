rule TTP_XOR_MULT_DOSStub_aa41 {
  strings:
    $key_aa41 = { fe 29 [2] 8a 31 [2] cd 33 [2] 8a 22 [2] c4 2e [2] c8 24 [2] df 2f [2] c4 61 [2] f9 }

  condition:
    any of them
}