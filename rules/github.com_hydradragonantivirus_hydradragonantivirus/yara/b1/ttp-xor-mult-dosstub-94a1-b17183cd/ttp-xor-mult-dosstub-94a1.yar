rule TTP_XOR_MULT_DOSStub_94a1 {
  strings:
    $key_94a1 = { c0 c9 [2] b4 d1 [2] f3 d3 [2] b4 c2 [2] fa ce [2] f6 c4 [2] e1 cf [2] fa 81 [2] c7 }

  condition:
    any of them
}