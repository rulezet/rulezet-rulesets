rule TTP_XOR_MULT_DOSStub_aa68 {
  strings:
    $key_aa68 = { fe 00 [2] 8a 18 [2] cd 1a [2] 8a 0b [2] c4 07 [2] c8 0d [2] df 06 [2] c4 48 [2] f9 }

  condition:
    any of them
}