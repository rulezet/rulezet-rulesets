rule TTP_XOR_MULT_DOSStub_a376 {
  strings:
    $key_a376 = { f7 1e [2] 83 06 [2] c4 04 [2] 83 15 [2] cd 19 [2] c1 13 [2] d6 18 [2] cd 56 [2] f0 }

  condition:
    any of them
}