rule TTP_XOR_MULT_DOSStub_aaf4 {
  strings:
    $key_aaf4 = { fe 9c [2] 8a 84 [2] cd 86 [2] 8a 97 [2] c4 9b [2] c8 91 [2] df 9a [2] c4 d4 [2] f9 }

  condition:
    any of them
}