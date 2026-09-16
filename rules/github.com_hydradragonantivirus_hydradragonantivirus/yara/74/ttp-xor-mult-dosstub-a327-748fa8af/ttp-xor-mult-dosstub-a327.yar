rule TTP_XOR_MULT_DOSStub_a327 {
  strings:
    $key_a327 = { f7 4f [2] 83 57 [2] c4 55 [2] 83 44 [2] cd 48 [2] c1 42 [2] d6 49 [2] cd 07 [2] f0 }

  condition:
    any of them
}