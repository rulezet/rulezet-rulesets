rule TTP_XOR_MULT_DOSStub_a348 {
  strings:
    $key_a348 = { f7 20 [2] 83 38 [2] c4 3a [2] 83 2b [2] cd 27 [2] c1 2d [2] d6 26 [2] cd 68 [2] f0 }

  condition:
    any of them
}