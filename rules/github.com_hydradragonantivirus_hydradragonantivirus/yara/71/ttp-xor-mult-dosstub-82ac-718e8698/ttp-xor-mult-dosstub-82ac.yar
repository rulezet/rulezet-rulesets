rule TTP_XOR_MULT_DOSStub_82ac {
  strings:
    $key_82ac = { d6 c4 [2] a2 dc [2] e5 de [2] a2 cf [2] ec c3 [2] e0 c9 [2] f7 c2 [2] ec 8c [2] d1 }

  condition:
    any of them
}