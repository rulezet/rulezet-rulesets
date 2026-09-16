rule TTP_XOR_MULT_DOSStub_aae0 {
  strings:
    $key_aae0 = { fe 88 [2] 8a 90 [2] cd 92 [2] 8a 83 [2] c4 8f [2] c8 85 [2] df 8e [2] c4 c0 [2] f9 }

  condition:
    any of them
}