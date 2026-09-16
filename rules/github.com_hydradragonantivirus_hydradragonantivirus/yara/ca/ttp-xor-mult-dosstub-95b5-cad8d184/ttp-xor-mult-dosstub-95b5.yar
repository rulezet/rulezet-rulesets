rule TTP_XOR_MULT_DOSStub_95b5 {
  strings:
    $key_95b5 = { c1 dd [2] b5 c5 [2] f2 c7 [2] b5 d6 [2] fb da [2] f7 d0 [2] e0 db [2] fb 95 [2] c6 }

  condition:
    any of them
}