rule TTP_XOR_MULT_DOSStub_a347 {
  strings:
    $key_a347 = { f7 2f [2] 83 37 [2] c4 35 [2] 83 24 [2] cd 28 [2] c1 22 [2] d6 29 [2] cd 67 [2] f0 }

  condition:
    any of them
}