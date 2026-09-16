rule TTP_XOR_MULT_DOSStub_a9a6 {
  strings:
    $key_a9a6 = { fd ce [2] 89 d6 [2] ce d4 [2] 89 c5 [2] c7 c9 [2] cb c3 [2] dc c8 [2] c7 86 [2] fa }

  condition:
    any of them
}