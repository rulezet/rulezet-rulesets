rule TTP_XOR_MULT_DOSStub_8fca {
  strings:
    $key_8fca = { db a2 [2] af ba [2] e8 b8 [2] af a9 [2] e1 a5 [2] ed af [2] fa a4 [2] e1 ea [2] dc }

  condition:
    any of them
}