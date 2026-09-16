rule TTP_XOR_MULT_DOSStub_8fd9 {
  strings:
    $key_8fd9 = { db b1 [2] af a9 [2] e8 ab [2] af ba [2] e1 b6 [2] ed bc [2] fa b7 [2] e1 f9 [2] dc }

  condition:
    any of them
}