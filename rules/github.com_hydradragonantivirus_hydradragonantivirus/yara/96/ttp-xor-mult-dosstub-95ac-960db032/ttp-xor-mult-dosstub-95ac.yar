rule TTP_XOR_MULT_DOSStub_95ac {
  strings:
    $key_95ac = { c1 c4 [2] b5 dc [2] f2 de [2] b5 cf [2] fb c3 [2] f7 c9 [2] e0 c2 [2] fb 8c [2] c6 }

  condition:
    any of them
}