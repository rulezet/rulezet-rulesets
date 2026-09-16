rule TTP_XOR_MULT_DOSStub_a9a1 {
  strings:
    $key_a9a1 = { fd c9 [2] 89 d1 [2] ce d3 [2] 89 c2 [2] c7 ce [2] cb c4 [2] dc cf [2] c7 81 [2] fa }

  condition:
    any of them
}