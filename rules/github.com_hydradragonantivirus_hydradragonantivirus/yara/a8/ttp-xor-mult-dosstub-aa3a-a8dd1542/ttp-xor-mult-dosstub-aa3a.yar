rule TTP_XOR_MULT_DOSStub_aa3a {
  strings:
    $key_aa3a = { fe 52 [2] 8a 4a [2] cd 48 [2] 8a 59 [2] c4 55 [2] c8 5f [2] df 54 [2] c4 1a [2] f9 }

  condition:
    any of them
}