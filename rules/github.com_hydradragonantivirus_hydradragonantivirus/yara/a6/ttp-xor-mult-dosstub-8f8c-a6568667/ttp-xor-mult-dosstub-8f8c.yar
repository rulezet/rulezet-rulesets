rule TTP_XOR_MULT_DOSStub_8f8c {
  strings:
    $key_8f8c = { db e4 [2] af fc [2] e8 fe [2] af ef [2] e1 e3 [2] ed e9 [2] fa e2 [2] e1 ac [2] dc }

  condition:
    any of them
}