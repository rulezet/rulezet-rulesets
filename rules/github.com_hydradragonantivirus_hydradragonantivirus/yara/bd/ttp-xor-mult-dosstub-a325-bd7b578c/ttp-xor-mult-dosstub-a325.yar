rule TTP_XOR_MULT_DOSStub_a325 {
  strings:
    $key_a325 = { f7 4d [2] 83 55 [2] c4 57 [2] 83 46 [2] cd 4a [2] c1 40 [2] d6 4b [2] cd 05 [2] f0 }

  condition:
    any of them
}