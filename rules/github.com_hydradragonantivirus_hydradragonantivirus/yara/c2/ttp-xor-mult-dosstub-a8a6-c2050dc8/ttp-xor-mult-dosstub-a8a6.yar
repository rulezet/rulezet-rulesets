rule TTP_XOR_MULT_DOSStub_a8a6 {
  strings:
    $key_a8a6 = { fc ce [2] 88 d6 [2] cf d4 [2] 88 c5 [2] c6 c9 [2] ca c3 [2] dd c8 [2] c6 86 [2] fb }

  condition:
    any of them
}