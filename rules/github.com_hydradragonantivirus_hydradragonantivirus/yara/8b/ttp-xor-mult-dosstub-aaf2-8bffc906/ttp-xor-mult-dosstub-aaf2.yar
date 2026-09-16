rule TTP_XOR_MULT_DOSStub_aaf2 {
  strings:
    $key_aaf2 = { fe 9a [2] 8a 82 [2] cd 80 [2] 8a 91 [2] c4 9d [2] c8 97 [2] df 9c [2] c4 d2 [2] f9 }

  condition:
    any of them
}