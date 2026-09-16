rule TTP_XOR_MULT_DOSStub_d9a6 {
  strings:
    $key_d9a6 = { 8d ce [2] f9 d6 [2] be d4 [2] f9 c5 [2] b7 c9 [2] bb c3 [2] ac c8 [2] b7 86 [2] 8a }

  condition:
    any of them
}