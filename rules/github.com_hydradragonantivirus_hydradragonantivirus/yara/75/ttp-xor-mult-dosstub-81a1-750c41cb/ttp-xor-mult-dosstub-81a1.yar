rule TTP_XOR_MULT_DOSStub_81a1 {
  strings:
    $key_81a1 = { d5 c9 [2] a1 d1 [2] e6 d3 [2] a1 c2 [2] ef ce [2] e3 c4 [2] f4 cf [2] ef 81 [2] d2 }

  condition:
    any of them
}