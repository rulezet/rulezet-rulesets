rule TTP_XOR_MULT_DOSStub_8f96 {
  strings:
    $key_8f96 = { db fe [2] af e6 [2] e8 e4 [2] af f5 [2] e1 f9 [2] ed f3 [2] fa f8 [2] e1 b6 [2] dc }

  condition:
    any of them
}