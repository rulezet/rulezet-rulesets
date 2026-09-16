rule TTP_XOR_MULT_DOSStub_85a0 {
  strings:
    $key_85a0 = { d1 c8 [2] a5 d0 [2] e2 d2 [2] a5 c3 [2] eb cf [2] e7 c5 [2] f0 ce [2] eb 80 [2] d6 }

  condition:
    any of them
}