rule TTP_XOR_MULT_DOSStub_a346 {
  strings:
    $key_a346 = { f7 2e [2] 83 36 [2] c4 34 [2] 83 25 [2] cd 29 [2] c1 23 [2] d6 28 [2] cd 66 [2] f0 }

  condition:
    any of them
}