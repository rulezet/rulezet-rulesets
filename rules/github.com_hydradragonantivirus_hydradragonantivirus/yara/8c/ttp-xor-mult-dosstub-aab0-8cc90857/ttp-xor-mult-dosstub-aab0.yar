rule TTP_XOR_MULT_DOSStub_aab0 {
  strings:
    $key_aab0 = { fe d8 [2] 8a c0 [2] cd c2 [2] 8a d3 [2] c4 df [2] c8 d5 [2] df de [2] c4 90 [2] f9 }

  condition:
    any of them
}