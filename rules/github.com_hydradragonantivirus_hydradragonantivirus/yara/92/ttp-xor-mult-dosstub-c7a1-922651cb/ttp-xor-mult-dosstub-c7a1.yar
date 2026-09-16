rule TTP_XOR_MULT_DOSStub_c7a1 {
  strings:
    $key_c7a1 = { 93 c9 [2] e7 d1 [2] a0 d3 [2] e7 c2 [2] a9 ce [2] a5 c4 [2] b2 cf [2] a9 81 [2] 94 }

  condition:
    any of them
}