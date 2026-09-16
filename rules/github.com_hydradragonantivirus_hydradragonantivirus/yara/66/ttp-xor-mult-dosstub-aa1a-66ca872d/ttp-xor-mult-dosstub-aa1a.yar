rule TTP_XOR_MULT_DOSStub_aa1a {
  strings:
    $key_aa1a = { fe 72 [2] 8a 6a [2] cd 68 [2] 8a 79 [2] c4 75 [2] c8 7f [2] df 74 [2] c4 3a [2] f9 }

  condition:
    any of them
}