rule TTP_XOR_MULT_DOSStub_90ac {
  strings:
    $key_90ac = { c4 c4 [2] b0 dc [2] f7 de [2] b0 cf [2] fe c3 [2] f2 c9 [2] e5 c2 [2] fe 8c [2] c3 }

  condition:
    any of them
}