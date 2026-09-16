rule TTP_XOR_MULT_DOSStub_92a6 {
  strings:
    $key_92a6 = { c6 ce [2] b2 d6 [2] f5 d4 [2] b2 c5 [2] fc c9 [2] f0 c3 [2] e7 c8 [2] fc 86 [2] c1 }

  condition:
    any of them
}