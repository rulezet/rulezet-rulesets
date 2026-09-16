rule TTP_XOR_MULT_DOSStub_aba6 {
  strings:
    $key_aba6 = { ff ce [2] 8b d6 [2] cc d4 [2] 8b c5 [2] c5 c9 [2] c9 c3 [2] de c8 [2] c5 86 [2] f8 }

  condition:
    any of them
}