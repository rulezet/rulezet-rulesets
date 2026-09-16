rule TTP_XOR_MULT_DOSStub_a312 {
  strings:
    $key_a312 = { f7 7a [2] 83 62 [2] c4 60 [2] 83 71 [2] cd 7d [2] c1 77 [2] d6 7c [2] cd 32 [2] f0 }

  condition:
    any of them
}