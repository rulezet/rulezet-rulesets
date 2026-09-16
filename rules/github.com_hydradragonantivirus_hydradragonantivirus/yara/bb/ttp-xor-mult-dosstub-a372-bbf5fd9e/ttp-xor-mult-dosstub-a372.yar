rule TTP_XOR_MULT_DOSStub_a372 {
  strings:
    $key_a372 = { f7 1a [2] 83 02 [2] c4 00 [2] 83 11 [2] cd 1d [2] c1 17 [2] d6 1c [2] cd 52 [2] f0 }

  condition:
    any of them
}