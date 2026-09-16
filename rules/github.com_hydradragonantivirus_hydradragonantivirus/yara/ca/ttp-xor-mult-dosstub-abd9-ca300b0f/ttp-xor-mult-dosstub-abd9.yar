rule TTP_XOR_MULT_DOSStub_abd9 {
  strings:
    $key_abd9 = { ff b1 [2] 8b a9 [2] cc ab [2] 8b ba [2] c5 b6 [2] c9 bc [2] de b7 [2] c5 f9 [2] f8 }

  condition:
    any of them
}