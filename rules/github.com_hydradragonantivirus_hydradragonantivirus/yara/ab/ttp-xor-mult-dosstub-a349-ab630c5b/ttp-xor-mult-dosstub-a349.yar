rule TTP_XOR_MULT_DOSStub_a349 {
  strings:
    $key_a349 = { f7 21 [2] 83 39 [2] c4 3b [2] 83 2a [2] cd 26 [2] c1 2c [2] d6 27 [2] cd 69 [2] f0 }

  condition:
    any of them
}