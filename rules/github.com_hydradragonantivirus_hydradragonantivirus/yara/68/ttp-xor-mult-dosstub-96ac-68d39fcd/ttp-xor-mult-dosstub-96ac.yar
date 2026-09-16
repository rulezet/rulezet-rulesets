rule TTP_XOR_MULT_DOSStub_96ac {
  strings:
    $key_96ac = { c2 c4 [2] b6 dc [2] f1 de [2] b6 cf [2] f8 c3 [2] f4 c9 [2] e3 c2 [2] f8 8c [2] c5 }

  condition:
    any of them
}