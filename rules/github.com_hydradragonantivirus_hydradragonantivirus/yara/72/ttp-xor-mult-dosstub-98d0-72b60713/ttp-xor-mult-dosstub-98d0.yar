rule TTP_XOR_MULT_DOSStub_98d0 {
  strings:
    $key_98d0 = { cc b8 [2] b8 a0 [2] ff a2 [2] b8 b3 [2] f6 bf [2] fa b5 [2] ed be [2] f6 f0 [2] cb }

  condition:
    any of them
}