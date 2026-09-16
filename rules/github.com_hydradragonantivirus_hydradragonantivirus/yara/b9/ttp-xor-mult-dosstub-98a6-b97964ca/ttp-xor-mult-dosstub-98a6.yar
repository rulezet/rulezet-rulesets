rule TTP_XOR_MULT_DOSStub_98a6 {
  strings:
    $key_98a6 = { cc ce [2] b8 d6 [2] ff d4 [2] b8 c5 [2] f6 c9 [2] fa c3 [2] ed c8 [2] f6 86 [2] cb }

  condition:
    any of them
}