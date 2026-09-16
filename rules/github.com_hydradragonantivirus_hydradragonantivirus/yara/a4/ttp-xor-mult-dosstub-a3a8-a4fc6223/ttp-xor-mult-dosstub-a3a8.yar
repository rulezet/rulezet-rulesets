rule TTP_XOR_MULT_DOSStub_a3a8 {
  strings:
    $key_a3a8 = { f7 c0 [2] 83 d8 [2] c4 da [2] 83 cb [2] cd c7 [2] c1 cd [2] d6 c6 [2] cd 88 [2] f0 }

  condition:
    any of them
}