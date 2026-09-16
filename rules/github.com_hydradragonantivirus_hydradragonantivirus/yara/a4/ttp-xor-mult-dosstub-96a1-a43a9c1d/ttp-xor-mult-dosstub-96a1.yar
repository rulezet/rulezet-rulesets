rule TTP_XOR_MULT_DOSStub_96a1 {
  strings:
    $key_96a1 = { c2 c9 [2] b6 d1 [2] f1 d3 [2] b6 c2 [2] f8 ce [2] f4 c4 [2] e3 cf [2] f8 81 [2] c5 }

  condition:
    any of them
}