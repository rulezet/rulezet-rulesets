rule TTP_XOR_MULT_DOSStub_d9a0 {
  strings:
    $key_d9a0 = { 8d c8 [2] f9 d0 [2] be d2 [2] f9 c3 [2] b7 cf [2] bb c5 [2] ac ce [2] b7 80 [2] 8a }

  condition:
    any of them
}