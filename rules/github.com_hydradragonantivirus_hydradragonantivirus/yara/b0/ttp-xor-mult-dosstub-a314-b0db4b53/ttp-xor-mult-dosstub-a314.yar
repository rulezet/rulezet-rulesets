rule TTP_XOR_MULT_DOSStub_a314 {
  strings:
    $key_a314 = { f7 7c [2] 83 64 [2] c4 66 [2] 83 77 [2] cd 7b [2] c1 71 [2] d6 7a [2] cd 34 [2] f0 }

  condition:
    any of them
}