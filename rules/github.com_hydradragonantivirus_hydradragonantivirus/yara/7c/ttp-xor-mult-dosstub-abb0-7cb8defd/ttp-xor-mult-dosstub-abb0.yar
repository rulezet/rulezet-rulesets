rule TTP_XOR_MULT_DOSStub_abb0 {
  strings:
    $key_abb0 = { ff d8 [2] 8b c0 [2] cc c2 [2] 8b d3 [2] c5 df [2] c9 d5 [2] de de [2] c5 90 [2] f8 }

  condition:
    any of them
}