rule TTP_XOR_MULT_DOSStub_a3a4 {
  strings:
    $key_a3a4 = { f7 cc [2] 83 d4 [2] c4 d6 [2] 83 c7 [2] cd cb [2] c1 c1 [2] d6 ca [2] cd 84 [2] f0 }

  condition:
    any of them
}