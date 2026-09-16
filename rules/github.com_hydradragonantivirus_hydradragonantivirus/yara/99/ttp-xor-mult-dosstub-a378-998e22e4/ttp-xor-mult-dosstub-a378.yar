rule TTP_XOR_MULT_DOSStub_a378 {
  strings:
    $key_a378 = { f7 10 [2] 83 08 [2] c4 0a [2] 83 1b [2] cd 17 [2] c1 1d [2] d6 16 [2] cd 58 [2] f0 }

  condition:
    any of them
}