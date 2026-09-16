rule TTP_XOR_MULT_DOSStub_8fbc {
  strings:
    $key_8fbc = { db d4 [2] af cc [2] e8 ce [2] af df [2] e1 d3 [2] ed d9 [2] fa d2 [2] e1 9c [2] dc }

  condition:
    any of them
}