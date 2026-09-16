rule TTP_XOR_MULT_DOSStub_e7a7 {
  strings:
    $key_e7a7 = { b3 cf [2] c7 d7 [2] 80 d5 [2] c7 c4 [2] 89 c8 [2] 85 c2 [2] 92 c9 [2] 89 87 [2] b4 }

  condition:
    any of them
}