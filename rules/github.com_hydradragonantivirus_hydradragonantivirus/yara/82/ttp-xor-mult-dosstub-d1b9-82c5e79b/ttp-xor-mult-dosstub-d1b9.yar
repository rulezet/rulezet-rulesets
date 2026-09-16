rule TTP_XOR_MULT_DOSStub_d1b9 {
  strings:
    $key_d1b9 = { 85 d1 [2] f1 c9 [2] b6 cb [2] f1 da [2] bf d6 [2] b3 dc [2] a4 d7 [2] bf 99 [2] 82 }

  condition:
    any of them
}