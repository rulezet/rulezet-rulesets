rule TTP_XOR_MULT_DOSStub_aba8 {
  strings:
    $key_aba8 = { ff c0 [2] 8b d8 [2] cc da [2] 8b cb [2] c5 c7 [2] c9 cd [2] de c6 [2] c5 88 [2] f8 }

  condition:
    any of them
}