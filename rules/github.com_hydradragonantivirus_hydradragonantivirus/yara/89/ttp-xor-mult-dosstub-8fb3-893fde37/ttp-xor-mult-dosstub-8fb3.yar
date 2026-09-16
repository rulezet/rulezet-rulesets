rule TTP_XOR_MULT_DOSStub_8fb3 {
  strings:
    $key_8fb3 = { db db [2] af c3 [2] e8 c1 [2] af d0 [2] e1 dc [2] ed d6 [2] fa dd [2] e1 93 [2] dc }

  condition:
    any of them
}