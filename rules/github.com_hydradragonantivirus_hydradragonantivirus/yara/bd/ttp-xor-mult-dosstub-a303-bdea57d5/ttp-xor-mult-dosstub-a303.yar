rule TTP_XOR_MULT_DOSStub_a303 {
  strings:
    $key_a303 = { f7 6b [2] 83 73 [2] c4 71 [2] 83 60 [2] cd 6c [2] c1 66 [2] d6 6d [2] cd 23 [2] f0 }

  condition:
    any of them
}