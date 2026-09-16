rule TTP_XOR_MULT_DOSStub_a361 {
  strings:
    $key_a361 = { f7 09 [2] 83 11 [2] c4 13 [2] 83 02 [2] cd 0e [2] c1 04 [2] d6 0f [2] cd 41 [2] f0 }

  condition:
    any of them
}