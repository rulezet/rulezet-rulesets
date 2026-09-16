rule TTP_XOR_MULT_DOSStub_d1b5 {
  strings:
    $key_d1b5 = { 85 dd [2] f1 c5 [2] b6 c7 [2] f1 d6 [2] bf da [2] b3 d0 [2] a4 db [2] bf 95 [2] 82 }

  condition:
    any of them
}