rule TTP_XOR_MULT_DOSStub_aac4 {
  strings:
    $key_aac4 = { fe ac [2] 8a b4 [2] cd b6 [2] 8a a7 [2] c4 ab [2] c8 a1 [2] df aa [2] c4 e4 [2] f9 }

  condition:
    any of them
}