rule TTP_XOR_MULT_DOSStub_d1a0 {
  strings:
    $key_d1a0 = { 85 c8 [2] f1 d0 [2] b6 d2 [2] f1 c3 [2] bf cf [2] b3 c5 [2] a4 ce [2] bf 80 [2] 82 }

  condition:
    any of them
}