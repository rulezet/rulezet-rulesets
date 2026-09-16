rule TTP_XOR_MULT_DOSStub_a3e9 {
  strings:
    $key_a3e9 = { f7 81 [2] 83 99 [2] c4 9b [2] 83 8a [2] cd 86 [2] c1 8c [2] d6 87 [2] cd c9 [2] f0 }

  condition:
    any of them
}