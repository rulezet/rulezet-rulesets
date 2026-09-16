rule TTP_XOR_MULT_DOSStub_a3e4 {
  strings:
    $key_a3e4 = { f7 8c [2] 83 94 [2] c4 96 [2] 83 87 [2] cd 8b [2] c1 81 [2] d6 8a [2] cd c4 [2] f0 }

  condition:
    any of them
}