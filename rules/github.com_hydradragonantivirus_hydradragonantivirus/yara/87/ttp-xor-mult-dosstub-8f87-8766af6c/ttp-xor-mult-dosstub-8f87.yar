rule TTP_XOR_MULT_DOSStub_8f87 {
  strings:
    $key_8f87 = { db ef [2] af f7 [2] e8 f5 [2] af e4 [2] e1 e8 [2] ed e2 [2] fa e9 [2] e1 a7 [2] dc }

  condition:
    any of them
}