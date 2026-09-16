rule TTP_XOR_MULT_DOSStub_8f9d {
  strings:
    $key_8f9d = { db f5 [2] af ed [2] e8 ef [2] af fe [2] e1 f2 [2] ed f8 [2] fa f3 [2] e1 bd [2] dc }

  condition:
    any of them
}