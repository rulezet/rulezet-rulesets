rule TTP_XOR_MULT_DOSStub_a356 {
  strings:
    $key_a356 = { f7 3e [2] 83 26 [2] c4 24 [2] 83 35 [2] cd 39 [2] c1 33 [2] d6 38 [2] cd 76 [2] f0 }

  condition:
    any of them
}