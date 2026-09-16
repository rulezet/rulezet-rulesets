rule TTP_XOR_MULT_DOSStub_a345 {
  strings:
    $key_a345 = { f7 2d [2] 83 35 [2] c4 37 [2] 83 26 [2] cd 2a [2] c1 20 [2] d6 2b [2] cd 65 [2] f0 }

  condition:
    any of them
}