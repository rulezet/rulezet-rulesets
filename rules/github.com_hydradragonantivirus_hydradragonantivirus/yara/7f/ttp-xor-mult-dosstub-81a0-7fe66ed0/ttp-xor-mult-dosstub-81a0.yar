rule TTP_XOR_MULT_DOSStub_81a0 {
  strings:
    $key_81a0 = { d5 c8 [2] a1 d0 [2] e6 d2 [2] a1 c3 [2] ef cf [2] e3 c5 [2] f4 ce [2] ef 80 [2] d2 }

  condition:
    any of them
}