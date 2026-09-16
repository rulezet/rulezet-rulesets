rule TTP_XOR_MULT_DOSStub_a9a7 {
  strings:
    $key_a9a7 = { fd cf [2] 89 d7 [2] ce d5 [2] 89 c4 [2] c7 c8 [2] cb c2 [2] dc c9 [2] c7 87 [2] fa }

  condition:
    any of them
}