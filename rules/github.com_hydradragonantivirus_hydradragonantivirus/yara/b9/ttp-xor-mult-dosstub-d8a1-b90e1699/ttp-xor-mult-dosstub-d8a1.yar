rule TTP_XOR_MULT_DOSStub_d8a1 {
  strings:
    $key_d8a1 = { 8c c9 [2] f8 d1 [2] bf d3 [2] f8 c2 [2] b6 ce [2] ba c4 [2] ad cf [2] b6 81 [2] 8b }

  condition:
    any of them
}