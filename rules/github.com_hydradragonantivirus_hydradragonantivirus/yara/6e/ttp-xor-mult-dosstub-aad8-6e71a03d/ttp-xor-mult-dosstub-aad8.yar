rule TTP_XOR_MULT_DOSStub_aad8 {
  strings:
    $key_aad8 = { fe b0 [2] 8a a8 [2] cd aa [2] 8a bb [2] c4 b7 [2] c8 bd [2] df b6 [2] c4 f8 [2] f9 }

  condition:
    any of them
}