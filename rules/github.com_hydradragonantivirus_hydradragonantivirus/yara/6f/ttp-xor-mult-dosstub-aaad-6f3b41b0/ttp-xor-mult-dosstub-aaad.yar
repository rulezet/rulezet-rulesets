rule TTP_XOR_MULT_DOSStub_aaad {
  strings:
    $key_aaad = { fe c5 [2] 8a dd [2] cd df [2] 8a ce [2] c4 c2 [2] c8 c8 [2] df c3 [2] c4 8d [2] f9 }

  condition:
    any of them
}