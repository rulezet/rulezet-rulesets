rule TTP_XOR_MULT_DOSStub_83a1 {
  strings:
    $key_83a1 = { d7 c9 [2] a3 d1 [2] e4 d3 [2] a3 c2 [2] ed ce [2] e1 c4 [2] f6 cf [2] ed 81 [2] d0 }

  condition:
    any of them
}