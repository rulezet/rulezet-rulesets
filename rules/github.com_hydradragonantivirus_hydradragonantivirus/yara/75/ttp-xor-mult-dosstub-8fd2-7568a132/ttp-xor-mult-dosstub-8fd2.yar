rule TTP_XOR_MULT_DOSStub_8fd2 {
  strings:
    $key_8fd2 = { db ba [2] af a2 [2] e8 a0 [2] af b1 [2] e1 bd [2] ed b7 [2] fa bc [2] e1 f2 [2] dc }

  condition:
    any of them
}