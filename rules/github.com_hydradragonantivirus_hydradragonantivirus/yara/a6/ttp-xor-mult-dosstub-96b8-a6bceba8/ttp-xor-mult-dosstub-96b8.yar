rule TTP_XOR_MULT_DOSStub_96b8 {
  strings:
    $key_96b8 = { c2 d0 [2] b6 c8 [2] f1 ca [2] b6 db [2] f8 d7 [2] f4 dd [2] e3 d6 [2] f8 98 [2] c5 }

  condition:
    any of them
}