rule TTP_XOR_MULT_DOSStub_a6b4 {
  strings:
    $key_a6b4 = { f2 dc [2] 86 c4 [2] c1 c6 [2] 86 d7 [2] c8 db [2] c4 d1 [2] d3 da [2] c8 94 [2] f5 }

  condition:
    any of them
}