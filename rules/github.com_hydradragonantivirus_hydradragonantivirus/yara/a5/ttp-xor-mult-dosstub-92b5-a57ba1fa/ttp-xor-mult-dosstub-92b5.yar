rule TTP_XOR_MULT_DOSStub_92b5 {
  strings:
    $key_92b5 = { c6 dd [2] b2 c5 [2] f5 c7 [2] b2 d6 [2] fc da [2] f0 d0 [2] e7 db [2] fc 95 [2] c1 }

  condition:
    any of them
}