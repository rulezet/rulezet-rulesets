rule TTP_XOR_MULT_DOSStub_aaab {
  strings:
    $key_aaab = { fe c3 [2] 8a db [2] cd d9 [2] 8a c8 [2] c4 c4 [2] c8 ce [2] df c5 [2] c4 8b [2] f9 }

  condition:
    any of them
}