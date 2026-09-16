rule TTP_XOR_MULT_DOSStub_a3a5 {
  strings:
    $key_a3a5 = { f7 cd [2] 83 d5 [2] c4 d7 [2] 83 c6 [2] cd ca [2] c1 c0 [2] d6 cb [2] cd 85 [2] f0 }

  condition:
    any of them
}