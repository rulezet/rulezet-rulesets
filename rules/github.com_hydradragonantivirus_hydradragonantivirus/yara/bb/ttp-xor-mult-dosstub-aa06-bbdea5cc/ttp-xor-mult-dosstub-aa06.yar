rule TTP_XOR_MULT_DOSStub_aa06 {
  strings:
    $key_aa06 = { fe 6e [2] 8a 76 [2] cd 74 [2] 8a 65 [2] c4 69 [2] c8 63 [2] df 68 [2] c4 26 [2] f9 }

  condition:
    any of them
}