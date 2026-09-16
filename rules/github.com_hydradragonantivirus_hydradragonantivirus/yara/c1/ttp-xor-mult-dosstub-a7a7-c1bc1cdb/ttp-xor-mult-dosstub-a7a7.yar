rule TTP_XOR_MULT_DOSStub_a7a7 {
  strings:
    $key_a7a7 = { f3 cf [2] 87 d7 [2] c0 d5 [2] 87 c4 [2] c9 c8 [2] c5 c2 [2] d2 c9 [2] c9 87 [2] f4 }

  condition:
    any of them
}