rule TTP_XOR_MULT_DOSStub_a3f5 {
  strings:
    $key_a3f5 = { f7 9d [2] 83 85 [2] c4 87 [2] 83 96 [2] cd 9a [2] c1 90 [2] d6 9b [2] cd d5 [2] f0 }

  condition:
    any of them
}