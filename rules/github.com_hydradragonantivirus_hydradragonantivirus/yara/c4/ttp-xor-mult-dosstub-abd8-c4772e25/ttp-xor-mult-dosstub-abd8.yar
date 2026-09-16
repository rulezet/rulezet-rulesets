rule TTP_XOR_MULT_DOSStub_abd8 {
  strings:
    $key_abd8 = { ff b0 [2] 8b a8 [2] cc aa [2] 8b bb [2] c5 b7 [2] c9 bd [2] de b6 [2] c5 f8 [2] f8 }

  condition:
    any of them
}