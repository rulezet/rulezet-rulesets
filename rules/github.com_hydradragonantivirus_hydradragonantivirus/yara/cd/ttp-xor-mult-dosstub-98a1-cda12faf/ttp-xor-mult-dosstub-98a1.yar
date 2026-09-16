rule TTP_XOR_MULT_DOSStub_98a1 {
  strings:
    $key_98a1 = { cc c9 [2] b8 d1 [2] ff d3 [2] b8 c2 [2] f6 ce [2] fa c4 [2] ed cf [2] f6 81 [2] cb }

  condition:
    any of them
}