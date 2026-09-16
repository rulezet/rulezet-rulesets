rule TTP_XOR_MULT_DOSStub_aa2c {
  strings:
    $key_aa2c = { fe 44 [2] 8a 5c [2] cd 5e [2] 8a 4f [2] c4 43 [2] c8 49 [2] df 42 [2] c4 0c [2] f9 }

  condition:
    any of them
}