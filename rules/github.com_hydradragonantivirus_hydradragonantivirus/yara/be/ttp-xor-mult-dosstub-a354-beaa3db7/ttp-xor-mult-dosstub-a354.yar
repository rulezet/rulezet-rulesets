rule TTP_XOR_MULT_DOSStub_a354 {
  strings:
    $key_a354 = { f7 3c [2] 83 24 [2] c4 26 [2] 83 37 [2] cd 3b [2] c1 31 [2] d6 3a [2] cd 74 [2] f0 }

  condition:
    any of them
}