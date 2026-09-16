rule TTP_XOR_MULT_DOSStub_a373 {
  strings:
    $key_a373 = { f7 1b [2] 83 03 [2] c4 01 [2] 83 10 [2] cd 1c [2] c1 16 [2] d6 1d [2] cd 53 [2] f0 }

  condition:
    any of them
}