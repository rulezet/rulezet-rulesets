rule TTP_XOR_MULT_DOSStub_a5a0 {
  strings:
    $key_a5a0 = { f1 c8 [2] 85 d0 [2] c2 d2 [2] 85 c3 [2] cb cf [2] c7 c5 [2] d0 ce [2] cb 80 [2] f6 }

  condition:
    any of them
}