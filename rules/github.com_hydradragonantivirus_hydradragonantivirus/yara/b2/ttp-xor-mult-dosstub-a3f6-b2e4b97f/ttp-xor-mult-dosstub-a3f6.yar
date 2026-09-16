rule TTP_XOR_MULT_DOSStub_a3f6 {
  strings:
    $key_a3f6 = { f7 9e [2] 83 86 [2] c4 84 [2] 83 95 [2] cd 99 [2] c1 93 [2] d6 98 [2] cd d6 [2] f0 }

  condition:
    any of them
}