rule TTP_XOR_MULT_DOSStub_d0a7 {
  strings:
    $key_d0a7 = { 84 cf [2] f0 d7 [2] b7 d5 [2] f0 c4 [2] be c8 [2] b2 c2 [2] a5 c9 [2] be 87 [2] 83 }

  condition:
    any of them
}