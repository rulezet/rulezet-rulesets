rule TTP_XOR_MULT_DOSStub_d1b4 {
  strings:
    $key_d1b4 = { 85 dc [2] f1 c4 [2] b6 c6 [2] f1 d7 [2] bf db [2] b3 d1 [2] a4 da [2] bf 94 [2] 82 }

  condition:
    any of them
}