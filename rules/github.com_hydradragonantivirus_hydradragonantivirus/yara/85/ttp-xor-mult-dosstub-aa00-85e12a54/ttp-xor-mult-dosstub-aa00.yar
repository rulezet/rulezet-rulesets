rule TTP_XOR_MULT_DOSStub_aa00 {
  strings:
    $key_aa00 = { fe 68 [2] 8a 70 [2] cd 72 [2] 8a 63 [2] c4 6f [2] c8 65 [2] df 6e [2] c4 20 [2] f9 }

  condition:
    any of them
}