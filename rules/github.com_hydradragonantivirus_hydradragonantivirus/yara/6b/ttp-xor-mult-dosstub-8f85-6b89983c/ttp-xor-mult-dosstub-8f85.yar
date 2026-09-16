rule TTP_XOR_MULT_DOSStub_8f85 {
  strings:
    $key_8f85 = { db ed [2] af f5 [2] e8 f7 [2] af e6 [2] e1 ea [2] ed e0 [2] fa eb [2] e1 a5 [2] dc }

  condition:
    any of them
}