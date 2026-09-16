rule TTP_XOR_MULT_DOSStub_8fbe {
  strings:
    $key_8fbe = { db d6 [2] af ce [2] e8 cc [2] af dd [2] e1 d1 [2] ed db [2] fa d0 [2] e1 9e [2] dc }

  condition:
    any of them
}