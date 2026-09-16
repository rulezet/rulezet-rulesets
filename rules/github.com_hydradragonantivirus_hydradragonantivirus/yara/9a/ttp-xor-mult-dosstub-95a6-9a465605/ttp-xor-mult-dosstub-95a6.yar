rule TTP_XOR_MULT_DOSStub_95a6 {
  strings:
    $key_95a6 = { c1 ce [2] b5 d6 [2] f2 d4 [2] b5 c5 [2] fb c9 [2] f7 c3 [2] e0 c8 [2] fb 86 [2] c6 }

  condition:
    any of them
}