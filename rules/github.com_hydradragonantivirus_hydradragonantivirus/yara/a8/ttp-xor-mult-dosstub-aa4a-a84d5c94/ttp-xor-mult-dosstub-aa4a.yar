rule TTP_XOR_MULT_DOSStub_aa4a {
  strings:
    $key_aa4a = { fe 22 [2] 8a 3a [2] cd 38 [2] 8a 29 [2] c4 25 [2] c8 2f [2] df 24 [2] c4 6a [2] f9 }

  condition:
    any of them
}