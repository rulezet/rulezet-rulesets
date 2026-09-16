rule TTP_XOR_MULT_DOSStub_aae6 {
  strings:
    $key_aae6 = { fe 8e [2] 8a 96 [2] cd 94 [2] 8a 85 [2] c4 89 [2] c8 83 [2] df 88 [2] c4 c6 [2] f9 }

  condition:
    any of them
}