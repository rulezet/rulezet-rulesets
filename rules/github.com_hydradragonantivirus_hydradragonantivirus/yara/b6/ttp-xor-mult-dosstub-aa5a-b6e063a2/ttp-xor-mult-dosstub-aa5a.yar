rule TTP_XOR_MULT_DOSStub_aa5a {
  strings:
    $key_aa5a = { fe 32 [2] 8a 2a [2] cd 28 [2] 8a 39 [2] c4 35 [2] c8 3f [2] df 34 [2] c4 7a [2] f9 }

  condition:
    any of them
}