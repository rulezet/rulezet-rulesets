rule TTP_XOR_MULT_DOSStub_abc8 {
  strings:
    $key_abc8 = { ff a0 [2] 8b b8 [2] cc ba [2] 8b ab [2] c5 a7 [2] c9 ad [2] de a6 [2] c5 e8 [2] f8 }

  condition:
    any of them
}