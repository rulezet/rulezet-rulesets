rule TTP_XOR_MULT_DOSStub_a359 {
  strings:
    $key_a359 = { f7 31 [2] 83 29 [2] c4 2b [2] 83 3a [2] cd 36 [2] c1 3c [2] d6 37 [2] cd 79 [2] f0 }

  condition:
    any of them
}