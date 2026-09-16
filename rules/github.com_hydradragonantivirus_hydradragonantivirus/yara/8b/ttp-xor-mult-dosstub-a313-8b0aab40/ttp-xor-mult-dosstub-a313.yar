rule TTP_XOR_MULT_DOSStub_a313 {
  strings:
    $key_a313 = { f7 7b [2] 83 63 [2] c4 61 [2] 83 70 [2] cd 7c [2] c1 76 [2] d6 7d [2] cd 33 [2] f0 }

  condition:
    any of them
}