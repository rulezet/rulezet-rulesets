rule TTP_XOR_MULT_DOSStub_a6b9 {
  strings:
    $key_a6b9 = { f2 d1 [2] 86 c9 [2] c1 cb [2] 86 da [2] c8 d6 [2] c4 dc [2] d3 d7 [2] c8 99 [2] f5 }

  condition:
    any of them
}