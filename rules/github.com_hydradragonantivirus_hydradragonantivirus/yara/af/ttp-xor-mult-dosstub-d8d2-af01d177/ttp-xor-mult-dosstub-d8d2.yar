rule TTP_XOR_MULT_DOSStub_d8d2 {
  strings:
    $key_d8d2 = { 8c ba [2] f8 a2 [2] bf a0 [2] f8 b1 [2] b6 bd [2] ba b7 [2] ad bc [2] b6 f2 [2] 8b }

  condition:
    any of them
}