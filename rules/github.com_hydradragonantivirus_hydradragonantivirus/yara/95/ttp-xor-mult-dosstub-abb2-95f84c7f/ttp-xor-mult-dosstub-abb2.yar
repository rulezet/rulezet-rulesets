rule TTP_XOR_MULT_DOSStub_abb2 {
  strings:
    $key_abb2 = { ff da [2] 8b c2 [2] cc c0 [2] 8b d1 [2] c5 dd [2] c9 d7 [2] de dc [2] c5 92 [2] f8 }

  condition:
    any of them
}