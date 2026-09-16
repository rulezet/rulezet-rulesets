rule TTP_XOR_MULT_DOSStub_aac2 {
  strings:
    $key_aac2 = { fe aa [2] 8a b2 [2] cd b0 [2] 8a a1 [2] c4 ad [2] c8 a7 [2] df ac [2] c4 e2 [2] f9 }

  condition:
    any of them
}