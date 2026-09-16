rule TTP_XOR_MULT_DOSStub_a363 {
  strings:
    $key_a363 = { f7 0b [2] 83 13 [2] c4 11 [2] 83 00 [2] cd 0c [2] c1 06 [2] d6 0d [2] cd 43 [2] f0 }

  condition:
    any of them
}