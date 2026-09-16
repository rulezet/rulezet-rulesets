rule TTP_XOR_MULT_DOSStub_aa61 {
  strings:
    $key_aa61 = { fe 09 [2] 8a 11 [2] cd 13 [2] 8a 02 [2] c4 0e [2] c8 04 [2] df 0f [2] c4 41 [2] f9 }

  condition:
    any of them
}