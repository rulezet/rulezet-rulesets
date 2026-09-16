rule TTP_XOR_MULT_DOSStub_a3f3 {
  strings:
    $key_a3f3 = { f7 9b [2] 83 83 [2] c4 81 [2] 83 90 [2] cd 9c [2] c1 96 [2] d6 9d [2] cd d3 [2] f0 }

  condition:
    any of them
}