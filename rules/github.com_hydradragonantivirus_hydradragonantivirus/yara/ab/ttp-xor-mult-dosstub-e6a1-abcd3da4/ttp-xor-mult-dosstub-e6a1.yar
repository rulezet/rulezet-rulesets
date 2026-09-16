rule TTP_XOR_MULT_DOSStub_e6a1 {
  strings:
    $key_e6a1 = { b2 c9 [2] c6 d1 [2] 81 d3 [2] c6 c2 [2] 88 ce [2] 84 c4 [2] 93 cf [2] 88 81 [2] b5 }

  condition:
    any of them
}