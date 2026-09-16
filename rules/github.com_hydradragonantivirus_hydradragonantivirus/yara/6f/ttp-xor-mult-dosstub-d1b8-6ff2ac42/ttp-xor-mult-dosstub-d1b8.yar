rule TTP_XOR_MULT_DOSStub_d1b8 {
  strings:
    $key_d1b8 = { 85 d0 [2] f1 c8 [2] b6 ca [2] f1 db [2] bf d7 [2] b3 dd [2] a4 d6 [2] bf 98 [2] 82 }

  condition:
    any of them
}