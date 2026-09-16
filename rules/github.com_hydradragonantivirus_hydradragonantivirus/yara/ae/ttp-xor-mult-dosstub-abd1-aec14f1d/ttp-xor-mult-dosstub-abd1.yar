rule TTP_XOR_MULT_DOSStub_abd1 {
  strings:
    $key_abd1 = { ff b9 [2] 8b a1 [2] cc a3 [2] 8b b2 [2] c5 be [2] c9 b4 [2] de bf [2] c5 f1 [2] f8 }

  condition:
    any of them
}