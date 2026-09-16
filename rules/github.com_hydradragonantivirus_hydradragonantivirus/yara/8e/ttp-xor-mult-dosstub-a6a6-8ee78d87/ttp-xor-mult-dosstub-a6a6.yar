rule TTP_XOR_MULT_DOSStub_a6a6 {
  strings:
    $key_a6a6 = { f2 ce [2] 86 d6 [2] c1 d4 [2] 86 c5 [2] c8 c9 [2] c4 c3 [2] d3 c8 [2] c8 86 [2] f5 }

  condition:
    any of them
}