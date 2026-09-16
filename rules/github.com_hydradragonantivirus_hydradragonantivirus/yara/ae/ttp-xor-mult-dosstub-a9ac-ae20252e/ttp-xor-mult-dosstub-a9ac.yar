rule TTP_XOR_MULT_DOSStub_a9ac {
  strings:
    $key_a9ac = { fd c4 [2] 89 dc [2] ce de [2] 89 cf [2] c7 c3 [2] cb c9 [2] dc c2 [2] c7 8c [2] fa }

  condition:
    any of them
}