rule TTP_XOR_MULT_DOSStub_aa67 {
  strings:
    $key_aa67 = { fe 0f [2] 8a 17 [2] cd 15 [2] 8a 04 [2] c4 08 [2] c8 02 [2] df 09 [2] c4 47 [2] f9 }

  condition:
    any of them
}