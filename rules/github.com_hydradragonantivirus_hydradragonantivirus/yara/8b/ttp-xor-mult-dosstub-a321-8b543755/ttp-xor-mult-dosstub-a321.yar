rule TTP_XOR_MULT_DOSStub_a321 {
  strings:
    $key_a321 = { f7 49 [2] 83 51 [2] c4 53 [2] 83 42 [2] cd 4e [2] c1 44 [2] d6 4f [2] cd 01 [2] f0 }

  condition:
    any of them
}