rule TTP_XOR_MULT_DOSStub_95a7 {
  strings:
    $key_95a7 = { c1 cf [2] b5 d7 [2] f2 d5 [2] b5 c4 [2] fb c8 [2] f7 c2 [2] e0 c9 [2] fb 87 [2] c6 }

  condition:
    any of them
}