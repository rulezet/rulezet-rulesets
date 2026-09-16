rule TTP_XOR_MULT_DOSStub_aba7 {
  strings:
    $key_aba7 = { ff cf [2] 8b d7 [2] cc d5 [2] 8b c4 [2] c5 c8 [2] c9 c2 [2] de c9 [2] c5 87 [2] f8 }

  condition:
    any of them
}