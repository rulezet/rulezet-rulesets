rule TTP_XOR_MULT_DOSStub_aaee {
  strings:
    $key_aaee = { fe 86 [2] 8a 9e [2] cd 9c [2] 8a 8d [2] c4 81 [2] c8 8b [2] df 80 [2] c4 ce [2] f9 }

  condition:
    any of them
}