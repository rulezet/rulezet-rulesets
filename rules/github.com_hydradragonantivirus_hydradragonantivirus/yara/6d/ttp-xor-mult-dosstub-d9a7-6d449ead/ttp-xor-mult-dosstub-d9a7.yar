rule TTP_XOR_MULT_DOSStub_d9a7 {
  strings:
    $key_d9a7 = { 8d cf [2] f9 d7 [2] be d5 [2] f9 c4 [2] b7 c8 [2] bb c2 [2] ac c9 [2] b7 87 [2] 8a }

  condition:
    any of them
}