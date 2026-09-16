rule TTP_XOR_MULT_DOSStub_b3a1 {
  strings:
    $key_b3a1 = { e7 c9 [2] 93 d1 [2] d4 d3 [2] 93 c2 [2] dd ce [2] d1 c4 [2] c6 cf [2] dd 81 [2] e0 }

  condition:
    any of them
}