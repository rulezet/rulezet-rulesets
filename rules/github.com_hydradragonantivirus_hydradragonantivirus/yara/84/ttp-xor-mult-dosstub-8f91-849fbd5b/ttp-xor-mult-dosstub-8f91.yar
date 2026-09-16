rule TTP_XOR_MULT_DOSStub_8f91 {
  strings:
    $key_8f91 = { db f9 [2] af e1 [2] e8 e3 [2] af f2 [2] e1 fe [2] ed f4 [2] fa ff [2] e1 b1 [2] dc }

  condition:
    any of them
}