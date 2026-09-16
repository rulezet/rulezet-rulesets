rule TTP_XOR_MULT_DOSStub_abb1 {
  strings:
    $key_abb1 = { ff d9 [2] 8b c1 [2] cc c3 [2] 8b d2 [2] c5 de [2] c9 d4 [2] de df [2] c5 91 [2] f8 }

  condition:
    any of them
}