rule TTP_XOR_MULT_DOSStub_98d1 {
  strings:
    $key_98d1 = { cc b9 [2] b8 a1 [2] ff a3 [2] b8 b2 [2] f6 be [2] fa b4 [2] ed bf [2] f6 f1 [2] cb }

  condition:
    any of them
}