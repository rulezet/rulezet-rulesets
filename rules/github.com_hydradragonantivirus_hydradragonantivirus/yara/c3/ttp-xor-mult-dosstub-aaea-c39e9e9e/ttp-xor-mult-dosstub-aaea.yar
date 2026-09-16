rule TTP_XOR_MULT_DOSStub_aaea {
  strings:
    $key_aaea = { fe 82 [2] 8a 9a [2] cd 98 [2] 8a 89 [2] c4 85 [2] c8 8f [2] df 84 [2] c4 ca [2] f9 }

  condition:
    any of them
}