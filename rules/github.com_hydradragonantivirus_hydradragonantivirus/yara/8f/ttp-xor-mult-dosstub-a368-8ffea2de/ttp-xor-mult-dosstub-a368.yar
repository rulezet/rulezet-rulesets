rule TTP_XOR_MULT_DOSStub_a368 {
  strings:
    $key_a368 = { f7 00 [2] 83 18 [2] c4 1a [2] 83 0b [2] cd 07 [2] c1 0d [2] d6 06 [2] cd 48 [2] f0 }

  condition:
    any of them
}