rule TTP_XOR_MULT_DOSStub_92a7 {
  strings:
    $key_92a7 = { c6 cf [2] b2 d7 [2] f5 d5 [2] b2 c4 [2] fc c8 [2] f0 c2 [2] e7 c9 [2] fc 87 [2] c1 }

  condition:
    any of them
}