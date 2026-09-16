rule TTP_XOR_MULT_DOSStub_b0a1 {
  strings:
    $key_b0a1 = { e4 c9 [2] 90 d1 [2] d7 d3 [2] 90 c2 [2] de ce [2] d2 c4 [2] c5 cf [2] de 81 [2] e3 }

  condition:
    any of them
}