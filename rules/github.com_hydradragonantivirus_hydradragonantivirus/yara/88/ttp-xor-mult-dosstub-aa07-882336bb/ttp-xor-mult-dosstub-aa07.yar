rule TTP_XOR_MULT_DOSStub_aa07 {
  strings:
    $key_aa07 = { fe 6f [2] 8a 77 [2] cd 75 [2] 8a 64 [2] c4 68 [2] c8 62 [2] df 69 [2] c4 27 [2] f9 }

  condition:
    any of them
}