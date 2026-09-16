rule TTP_XOR_MULT_DOSStub_c1a1 {
  strings:
    $key_c1a1 = { 95 c9 [2] e1 d1 [2] a6 d3 [2] e1 c2 [2] af ce [2] a3 c4 [2] b4 cf [2] af 81 [2] 92 }

  condition:
    any of them
}