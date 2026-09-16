rule TTP_XOR_MULT_DOSStub_d8a0 {
  strings:
    $key_d8a0 = { 8c c8 [2] f8 d0 [2] bf d2 [2] f8 c3 [2] b6 cf [2] ba c5 [2] ad ce [2] b6 80 [2] 8b }

  condition:
    any of them
}