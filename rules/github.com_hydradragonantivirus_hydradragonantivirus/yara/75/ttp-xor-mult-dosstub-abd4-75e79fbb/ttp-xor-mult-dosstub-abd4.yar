rule TTP_XOR_MULT_DOSStub_abd4 {
  strings:
    $key_abd4 = { ff bc [2] 8b a4 [2] cc a6 [2] 8b b7 [2] c5 bb [2] c9 b1 [2] de ba [2] c5 f4 [2] f8 }

  condition:
    any of them
}