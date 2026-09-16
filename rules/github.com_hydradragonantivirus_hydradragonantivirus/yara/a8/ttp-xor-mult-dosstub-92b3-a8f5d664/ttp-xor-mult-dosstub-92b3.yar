rule TTP_XOR_MULT_DOSStub_92b3 {
  strings:
    $key_92b3 = { c6 db [2] b2 c3 [2] f5 c1 [2] b2 d0 [2] fc dc [2] f0 d6 [2] e7 dd [2] fc 93 [2] c1 }

  condition:
    any of them
}