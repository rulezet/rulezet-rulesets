rule TTP_XOR_MULT_DOSStub_a6a9 {
  strings:
    $key_a6a9 = { f2 c1 [2] 86 d9 [2] c1 db [2] 86 ca [2] c8 c6 [2] c4 cc [2] d3 c7 [2] c8 89 [2] f5 }

  condition:
    any of them
}