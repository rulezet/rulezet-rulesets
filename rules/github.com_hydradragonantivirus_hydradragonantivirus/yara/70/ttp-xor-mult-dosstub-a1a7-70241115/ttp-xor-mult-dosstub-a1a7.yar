rule TTP_XOR_MULT_DOSStub_a1a7 {
  strings:
    $key_a1a7 = { f5 cf [2] 81 d7 [2] c6 d5 [2] 81 c4 [2] cf c8 [2] c3 c2 [2] d4 c9 [2] cf 87 [2] f2 }

  condition:
    any of them
}