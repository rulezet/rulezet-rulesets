rule TTP_XOR_MULT_DOSStub_a362 {
  strings:
    $key_a362 = { f7 0a [2] 83 12 [2] c4 10 [2] 83 01 [2] cd 0d [2] c1 07 [2] d6 0c [2] cd 42 [2] f0 }

  condition:
    any of them
}