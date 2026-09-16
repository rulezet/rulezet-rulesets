rule TTP_XOR_MULT_DOSStub_8da7 {
  strings:
    $key_8da7 = { d9 cf [2] ad d7 [2] ea d5 [2] ad c4 [2] e3 c8 [2] ef c2 [2] f8 c9 [2] e3 87 [2] de }

  condition:
    any of them
}