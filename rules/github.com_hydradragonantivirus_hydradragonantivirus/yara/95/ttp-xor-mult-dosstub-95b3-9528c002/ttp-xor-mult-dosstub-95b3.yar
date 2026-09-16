rule TTP_XOR_MULT_DOSStub_95b3 {
  strings:
    $key_95b3 = { c1 db [2] b5 c3 [2] f2 c1 [2] b5 d0 [2] fb dc [2] f7 d6 [2] e0 dd [2] fb 93 [2] c6 }

  condition:
    any of them
}