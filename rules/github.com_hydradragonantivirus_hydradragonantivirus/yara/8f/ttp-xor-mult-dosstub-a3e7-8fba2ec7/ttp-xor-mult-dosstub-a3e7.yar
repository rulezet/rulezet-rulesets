rule TTP_XOR_MULT_DOSStub_a3e7 {
  strings:
    $key_a3e7 = { f7 8f [2] 83 97 [2] c4 95 [2] 83 84 [2] cd 88 [2] c1 82 [2] d6 89 [2] cd c7 [2] f0 }

  condition:
    any of them
}