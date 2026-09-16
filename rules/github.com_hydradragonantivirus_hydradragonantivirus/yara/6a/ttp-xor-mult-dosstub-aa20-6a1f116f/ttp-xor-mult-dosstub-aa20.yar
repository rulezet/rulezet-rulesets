rule TTP_XOR_MULT_DOSStub_aa20 {
  strings:
    $key_aa20 = { fe 48 [2] 8a 50 [2] cd 52 [2] 8a 43 [2] c4 4f [2] c8 45 [2] df 4e [2] c4 00 [2] f9 }

  condition:
    any of them
}