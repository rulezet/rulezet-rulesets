rule TTP_XOR_MULT_DOSStub_a357 {
  strings:
    $key_a357 = { f7 3f [2] 83 27 [2] c4 25 [2] 83 34 [2] cd 38 [2] c1 32 [2] d6 39 [2] cd 77 [2] f0 }

  condition:
    any of them
}