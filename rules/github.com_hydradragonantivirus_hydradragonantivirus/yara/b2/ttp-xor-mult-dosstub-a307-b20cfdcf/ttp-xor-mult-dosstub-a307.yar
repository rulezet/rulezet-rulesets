rule TTP_XOR_MULT_DOSStub_a307 {
  strings:
    $key_a307 = { f7 6f [2] 83 77 [2] c4 75 [2] 83 64 [2] cd 68 [2] c1 62 [2] d6 69 [2] cd 27 [2] f0 }

  condition:
    any of them
}