rule TTP_XOR_MULT_DOSStub_a6a4 {
  strings:
    $key_a6a4 = { f2 cc [2] 86 d4 [2] c1 d6 [2] 86 c7 [2] c8 cb [2] c4 c1 [2] d3 ca [2] c8 84 [2] f5 }

  condition:
    any of them
}