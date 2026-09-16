rule TTP_XOR_MULT_DOSStub_8fb1 {
  strings:
    $key_8fb1 = { db d9 [2] af c1 [2] e8 c3 [2] af d2 [2] e1 de [2] ed d4 [2] fa df [2] e1 91 [2] dc }

  condition:
    any of them
}