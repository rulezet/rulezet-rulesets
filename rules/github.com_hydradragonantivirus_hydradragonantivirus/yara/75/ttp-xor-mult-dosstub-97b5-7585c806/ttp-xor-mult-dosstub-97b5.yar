rule TTP_XOR_MULT_DOSStub_97b5 {
  strings:
    $key_97b5 = { c3 dd [2] b7 c5 [2] f0 c7 [2] b7 d6 [2] f9 da [2] f5 d0 [2] e2 db [2] f9 95 [2] c4 }

  condition:
    any of them
}