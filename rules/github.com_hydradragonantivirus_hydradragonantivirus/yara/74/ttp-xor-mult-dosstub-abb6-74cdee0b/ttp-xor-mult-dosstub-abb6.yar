rule TTP_XOR_MULT_DOSStub_abb6 {
  strings:
    $key_abb6 = { ff de [2] 8b c6 [2] cc c4 [2] 8b d5 [2] c5 d9 [2] c9 d3 [2] de d8 [2] c5 96 [2] f8 }

  condition:
    any of them
}