rule TTP_XOR_MULT_DOSStub_90a7 {
  strings:
    $key_90a7 = { c4 cf [2] b0 d7 [2] f7 d5 [2] b0 c4 [2] fe c8 [2] f2 c2 [2] e5 c9 [2] fe 87 [2] c3 }

  condition:
    any of them
}