rule TTP_XOR_MULT_DOSStub_d0a0 {
  strings:
    $key_d0a0 = { 84 c8 [2] f0 d0 [2] b7 d2 [2] f0 c3 [2] be cf [2] b2 c5 [2] a5 ce [2] be 80 [2] 83 }

  condition:
    any of them
}