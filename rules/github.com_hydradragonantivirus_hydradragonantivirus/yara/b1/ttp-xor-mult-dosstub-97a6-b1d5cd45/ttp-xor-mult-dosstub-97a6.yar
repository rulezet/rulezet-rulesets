rule TTP_XOR_MULT_DOSStub_97a6 {
  strings:
    $key_97a6 = { c3 ce [2] b7 d6 [2] f0 d4 [2] b7 c5 [2] f9 c9 [2] f5 c3 [2] e2 c8 [2] f9 86 [2] c4 }

  condition:
    any of them
}