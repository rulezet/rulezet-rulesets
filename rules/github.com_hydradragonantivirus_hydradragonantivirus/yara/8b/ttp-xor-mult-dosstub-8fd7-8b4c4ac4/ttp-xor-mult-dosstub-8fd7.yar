rule TTP_XOR_MULT_DOSStub_8fd7 {
  strings:
    $key_8fd7 = { db bf [2] af a7 [2] e8 a5 [2] af b4 [2] e1 b8 [2] ed b2 [2] fa b9 [2] e1 f7 [2] dc }

  condition:
    any of them
}