rule TTP_XOR_MULT_DOSStub_abb4 {
  strings:
    $key_abb4 = { ff dc [2] 8b c4 [2] cc c6 [2] 8b d7 [2] c5 db [2] c9 d1 [2] de da [2] c5 94 [2] f8 }

  condition:
    any of them
}