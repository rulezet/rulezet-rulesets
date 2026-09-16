rule TTP_XOR_MULT_DOSStub_a3a9 {
  strings:
    $key_a3a9 = { f7 c1 [2] 83 d9 [2] c4 db [2] 83 ca [2] cd c6 [2] c1 cc [2] d6 c7 [2] cd 89 [2] f0 }

  condition:
    any of them
}