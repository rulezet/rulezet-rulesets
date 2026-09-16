rule TTP_XOR_MULT_DOSStub_d5b9 {
  strings:
    $key_d5b9 = { 81 d1 [2] f5 c9 [2] b2 cb [2] f5 da [2] bb d6 [2] b7 dc [2] a0 d7 [2] bb 99 [2] 86 }

  condition:
    any of them
}