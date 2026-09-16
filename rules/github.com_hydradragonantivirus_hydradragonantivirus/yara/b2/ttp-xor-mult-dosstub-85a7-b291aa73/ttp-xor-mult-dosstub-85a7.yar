rule TTP_XOR_MULT_DOSStub_85a7 {
  strings:
    $key_85a7 = { d1 cf [2] a5 d7 [2] e2 d5 [2] a5 c4 [2] eb c8 [2] e7 c2 [2] f0 c9 [2] eb 87 [2] d6 }

  condition:
    any of them
}