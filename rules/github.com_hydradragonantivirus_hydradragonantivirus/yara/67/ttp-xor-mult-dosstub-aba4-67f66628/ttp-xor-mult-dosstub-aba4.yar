rule TTP_XOR_MULT_DOSStub_aba4 {
  strings:
    $key_aba4 = { ff cc [2] 8b d4 [2] cc d6 [2] 8b c7 [2] c5 cb [2] c9 c1 [2] de ca [2] c5 84 [2] f8 }

  condition:
    any of them
}