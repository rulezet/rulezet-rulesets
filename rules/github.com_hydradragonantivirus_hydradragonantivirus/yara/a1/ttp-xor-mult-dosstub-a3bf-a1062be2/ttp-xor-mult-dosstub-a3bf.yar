rule TTP_XOR_MULT_DOSStub_a3bf {
  strings:
    $key_a3bf = { f7 d7 [2] 83 cf [2] c4 cd [2] 83 dc [2] cd d0 [2] c1 da [2] d6 d1 [2] cd 9f [2] f0 }

  condition:
    any of them
}