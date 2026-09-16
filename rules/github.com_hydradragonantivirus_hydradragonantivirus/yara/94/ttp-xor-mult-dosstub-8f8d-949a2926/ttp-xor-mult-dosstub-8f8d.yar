rule TTP_XOR_MULT_DOSStub_8f8d {
  strings:
    $key_8f8d = { db e5 [2] af fd [2] e8 ff [2] af ee [2] e1 e2 [2] ed e8 [2] fa e3 [2] e1 ad [2] dc }

  condition:
    any of them
}