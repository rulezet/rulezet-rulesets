rule TTP_XOR_MULT_DOSStub_8fb2 {
  strings:
    $key_8fb2 = { db da [2] af c2 [2] e8 c0 [2] af d1 [2] e1 dd [2] ed d7 [2] fa dc [2] e1 92 [2] dc }

  condition:
    any of them
}