rule TTP_XOR_MULT_DOSStub_96b3 {
  strings:
    $key_96b3 = { c2 db [2] b6 c3 [2] f1 c1 [2] b6 d0 [2] f8 dc [2] f4 d6 [2] e3 dd [2] f8 93 [2] c5 }

  condition:
    any of them
}