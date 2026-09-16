rule TTP_XOR_MULT_DOSStub_a3bd {
  strings:
    $key_a3bd = { f7 d5 [2] 83 cd [2] c4 cf [2] 83 de [2] cd d2 [2] c1 d8 [2] d6 d3 [2] cd 9d [2] f0 }

  condition:
    any of them
}