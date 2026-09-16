rule TTP_XOR_MULT_DOSStub_a355 {
  strings:
    $key_a355 = { f7 3d [2] 83 25 [2] c4 27 [2] 83 36 [2] cd 3a [2] c1 30 [2] d6 3b [2] cd 75 [2] f0 }

  condition:
    any of them
}