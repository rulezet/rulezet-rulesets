rule TTP_XOR_MULT_DOSStub_e3a7 {
  strings:
    $key_e3a7 = { b7 cf [2] c3 d7 [2] 84 d5 [2] c3 c4 [2] 8d c8 [2] 81 c2 [2] 96 c9 [2] 8d 87 [2] b0 }

  condition:
    any of them
}