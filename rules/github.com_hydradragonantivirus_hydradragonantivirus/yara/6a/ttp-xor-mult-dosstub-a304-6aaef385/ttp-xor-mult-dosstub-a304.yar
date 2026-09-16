rule TTP_XOR_MULT_DOSStub_a304 {
  strings:
    $key_a304 = { f7 6c [2] 83 74 [2] c4 76 [2] 83 67 [2] cd 6b [2] c1 61 [2] d6 6a [2] cd 24 [2] f0 }

  condition:
    any of them
}