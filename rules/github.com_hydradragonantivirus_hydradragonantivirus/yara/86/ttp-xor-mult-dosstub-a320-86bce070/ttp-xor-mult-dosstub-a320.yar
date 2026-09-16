rule TTP_XOR_MULT_DOSStub_a320 {
  strings:
    $key_a320 = { f7 48 [2] 83 50 [2] c4 52 [2] 83 43 [2] cd 4f [2] c1 45 [2] d6 4e [2] cd 00 [2] f0 }

  condition:
    any of them
}