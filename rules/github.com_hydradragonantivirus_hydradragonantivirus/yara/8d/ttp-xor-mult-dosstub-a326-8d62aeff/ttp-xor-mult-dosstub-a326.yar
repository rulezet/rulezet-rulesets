rule TTP_XOR_MULT_DOSStub_a326 {
  strings:
    $key_a326 = { f7 4e [2] 83 56 [2] c4 54 [2] 83 45 [2] cd 49 [2] c1 43 [2] d6 48 [2] cd 06 [2] f0 }

  condition:
    any of them
}