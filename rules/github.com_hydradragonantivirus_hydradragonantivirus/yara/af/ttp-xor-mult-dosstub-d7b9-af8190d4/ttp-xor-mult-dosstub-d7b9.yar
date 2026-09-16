rule TTP_XOR_MULT_DOSStub_d7b9 {
  strings:
    $key_d7b9 = { 83 d1 [2] f7 c9 [2] b0 cb [2] f7 da [2] b9 d6 [2] b5 dc [2] a2 d7 [2] b9 99 [2] 84 }

  condition:
    any of them
}