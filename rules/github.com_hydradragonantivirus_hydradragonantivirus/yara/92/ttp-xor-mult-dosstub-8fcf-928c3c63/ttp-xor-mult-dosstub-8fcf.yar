rule TTP_XOR_MULT_DOSStub_8fcf {
  strings:
    $key_8fcf = { db a7 [2] af bf [2] e8 bd [2] af ac [2] e1 a0 [2] ed aa [2] fa a1 [2] e1 ef [2] dc }

  condition:
    any of them
}