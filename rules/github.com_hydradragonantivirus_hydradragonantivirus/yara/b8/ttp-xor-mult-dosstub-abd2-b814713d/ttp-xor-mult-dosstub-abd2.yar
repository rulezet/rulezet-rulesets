rule TTP_XOR_MULT_DOSStub_abd2 {
  strings:
    $key_abd2 = { ff ba [2] 8b a2 [2] cc a0 [2] 8b b1 [2] c5 bd [2] c9 b7 [2] de bc [2] c5 f2 [2] f8 }

  condition:
    any of them
}