rule TTP_XOR_MULT_DOSStub_97a0 {
  strings:
    $key_97a0 = { c3 c8 [2] b7 d0 [2] f0 d2 [2] b7 c3 [2] f9 cf [2] f5 c5 [2] e2 ce [2] f9 80 [2] c4 }

  condition:
    any of them
}