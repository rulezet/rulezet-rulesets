rule TTP_XOR_MULT_DOSStub_e2a1 {
  strings:
    $key_e2a1 = { b6 c9 [2] c2 d1 [2] 85 d3 [2] c2 c2 [2] 8c ce [2] 80 c4 [2] 97 cf [2] 8c 81 [2] b1 }

  condition:
    any of them
}