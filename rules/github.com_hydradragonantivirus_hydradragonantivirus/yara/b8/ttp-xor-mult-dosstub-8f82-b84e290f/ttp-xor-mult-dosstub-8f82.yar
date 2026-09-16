rule TTP_XOR_MULT_DOSStub_8f82 {
  strings:
    $key_8f82 = { db ea [2] af f2 [2] e8 f0 [2] af e1 [2] e1 ed [2] ed e7 [2] fa ec [2] e1 a2 [2] dc }

  condition:
    any of them
}