rule TTP_XOR_MULT_DOSStub_8fac {
  strings:
    $key_8fac = { db c4 [2] af dc [2] e8 de [2] af cf [2] e1 c3 [2] ed c9 [2] fa c2 [2] e1 8c [2] dc }

  condition:
    any of them
}