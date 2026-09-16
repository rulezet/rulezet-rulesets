rule TTP_XOR_MULT_DOSStub_aae9 {
  strings:
    $key_aae9 = { fe 81 [2] 8a 99 [2] cd 9b [2] 8a 8a [2] c4 86 [2] c8 8c [2] df 87 [2] c4 c9 [2] f9 }

  condition:
    any of them
}