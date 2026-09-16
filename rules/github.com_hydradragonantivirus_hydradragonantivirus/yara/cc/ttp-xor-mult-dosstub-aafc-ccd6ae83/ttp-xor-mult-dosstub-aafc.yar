rule TTP_XOR_MULT_DOSStub_aafc {
  strings:
    $key_aafc = { fe 94 [2] 8a 8c [2] cd 8e [2] 8a 9f [2] c4 93 [2] c8 99 [2] df 92 [2] c4 dc [2] f9 }

  condition:
    any of them
}