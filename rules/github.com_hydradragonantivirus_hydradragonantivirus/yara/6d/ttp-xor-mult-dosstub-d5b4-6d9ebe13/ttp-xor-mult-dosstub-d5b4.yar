rule TTP_XOR_MULT_DOSStub_d5b4 {
  strings:
    $key_d5b4 = { 81 dc [2] f5 c4 [2] b2 c6 [2] f5 d7 [2] bb db [2] b7 d1 [2] a0 da [2] bb 94 [2] 86 }

  condition:
    any of them
}