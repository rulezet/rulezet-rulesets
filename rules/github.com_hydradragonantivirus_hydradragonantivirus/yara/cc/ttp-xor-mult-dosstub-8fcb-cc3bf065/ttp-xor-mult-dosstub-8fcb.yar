rule TTP_XOR_MULT_DOSStub_8fcb {
  strings:
    $key_8fcb = { db a3 [2] af bb [2] e8 b9 [2] af a8 [2] e1 a4 [2] ed ae [2] fa a5 [2] e1 eb [2] dc }

  condition:
    any of them
}