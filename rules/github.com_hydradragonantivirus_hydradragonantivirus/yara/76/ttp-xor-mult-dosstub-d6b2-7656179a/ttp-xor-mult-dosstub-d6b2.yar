rule TTP_XOR_MULT_DOSStub_d6b2 {
  strings:
    $key_d6b2 = { 82 da [2] f6 c2 [2] b1 c0 [2] f6 d1 [2] b8 dd [2] b4 d7 [2] a3 dc [2] b8 92 [2] 85 }

  condition:
    any of them
}