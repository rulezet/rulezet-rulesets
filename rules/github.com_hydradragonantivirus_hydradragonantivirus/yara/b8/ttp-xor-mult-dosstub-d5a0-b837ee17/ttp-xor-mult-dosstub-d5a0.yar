rule TTP_XOR_MULT_DOSStub_d5a0 {
  strings:
    $key_d5a0 = { 81 c8 [2] f5 d0 [2] b2 d2 [2] f5 c3 [2] bb cf [2] b7 c5 [2] a0 ce [2] bb 80 [2] 86 }

  condition:
    any of them
}