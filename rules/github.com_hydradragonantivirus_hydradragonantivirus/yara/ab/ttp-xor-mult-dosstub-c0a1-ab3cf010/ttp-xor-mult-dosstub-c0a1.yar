rule TTP_XOR_MULT_DOSStub_c0a1 {
  strings:
    $key_c0a1 = { 94 c9 [2] e0 d1 [2] a7 d3 [2] e0 c2 [2] ae ce [2] a2 c4 [2] b5 cf [2] ae 81 [2] 93 }

  condition:
    any of them
}