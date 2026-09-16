rule TTP_XOR_MULT_DOSStub_d6a0 {
  strings:
    $key_d6a0 = { 82 c8 [2] f6 d0 [2] b1 d2 [2] f6 c3 [2] b8 cf [2] b4 c5 [2] a3 ce [2] b8 80 [2] 85 }

  condition:
    any of them
}