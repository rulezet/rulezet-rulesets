rule TTP_XOR_MULT_DOSStub_8fa6 {
  strings:
    $key_8fa6 = { db ce [2] af d6 [2] e8 d4 [2] af c5 [2] e1 c9 [2] ed c3 [2] fa c8 [2] e1 86 [2] dc }

  condition:
    any of them
}