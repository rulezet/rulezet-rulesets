rule TTP_XOR_MULT_DOSStub_aae1 {
  strings:
    $key_aae1 = { fe 89 [2] 8a 91 [2] cd 93 [2] 8a 82 [2] c4 8e [2] c8 84 [2] df 8f [2] c4 c1 [2] f9 }

  condition:
    any of them
}