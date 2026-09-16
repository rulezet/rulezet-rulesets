rule TTP_XOR_MULT_DOSStub_a5ac {
  strings:
    $key_a5ac = { f1 c4 [2] 85 dc [2] c2 de [2] 85 cf [2] cb c3 [2] c7 c9 [2] d0 c2 [2] cb 8c [2] f6 }

  condition:
    any of them
}