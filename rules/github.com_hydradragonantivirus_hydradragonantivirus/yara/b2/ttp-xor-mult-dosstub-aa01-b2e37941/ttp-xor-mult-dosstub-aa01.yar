rule TTP_XOR_MULT_DOSStub_aa01 {
  strings:
    $key_aa01 = { fe 69 [2] 8a 71 [2] cd 73 [2] 8a 62 [2] c4 6e [2] c8 64 [2] df 6f [2] c4 21 [2] f9 }

  condition:
    any of them
}