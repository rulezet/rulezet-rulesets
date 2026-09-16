rule TTP_XOR_MULT_DOSStub_d8a7 {
  strings:
    $key_d8a7 = { 8c cf [2] f8 d7 [2] bf d5 [2] f8 c4 [2] b6 c8 [2] ba c2 [2] ad c9 [2] b6 87 [2] 8b }

  condition:
    any of them
}