rule TTP_XOR_MULT_DOSStub_92a0 {
  strings:
    $key_92a0 = { c6 c8 [2] b2 d0 [2] f5 d2 [2] b2 c3 [2] fc cf [2] f0 c5 [2] e7 ce [2] fc 80 [2] c1 }

  condition:
    any of them
}