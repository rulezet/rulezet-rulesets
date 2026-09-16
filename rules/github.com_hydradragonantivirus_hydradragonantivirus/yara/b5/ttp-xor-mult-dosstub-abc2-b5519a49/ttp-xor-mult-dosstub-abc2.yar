rule TTP_XOR_MULT_DOSStub_abc2 {
  strings:
    $key_abc2 = { ff aa [2] 8b b2 [2] cc b0 [2] 8b a1 [2] c5 ad [2] c9 a7 [2] de ac [2] c5 e2 [2] f8 }

  condition:
    any of them
}