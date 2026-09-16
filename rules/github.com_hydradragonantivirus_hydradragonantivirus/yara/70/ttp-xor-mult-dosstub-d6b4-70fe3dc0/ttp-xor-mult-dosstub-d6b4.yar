rule TTP_XOR_MULT_DOSStub_d6b4 {
  strings:
    $key_d6b4 = { 82 dc [2] f6 c4 [2] b1 c6 [2] f6 d7 [2] b8 db [2] b4 d1 [2] a3 da [2] b8 94 [2] 85 }

  condition:
    any of them
}