rule TTP_XOR_MULT_DOSStub_a3ef {
  strings:
    $key_a3ef = { f7 87 [2] 83 9f [2] c4 9d [2] 83 8c [2] cd 80 [2] c1 8a [2] d6 81 [2] cd cf [2] f0 }

  condition:
    any of them
}