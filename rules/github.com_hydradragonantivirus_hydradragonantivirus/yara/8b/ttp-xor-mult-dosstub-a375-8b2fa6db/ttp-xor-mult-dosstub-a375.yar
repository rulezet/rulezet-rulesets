rule TTP_XOR_MULT_DOSStub_a375 {
  strings:
    $key_a375 = { f7 1d [2] 83 05 [2] c4 07 [2] 83 16 [2] cd 1a [2] c1 10 [2] d6 1b [2] cd 55 [2] f0 }

  condition:
    any of them
}