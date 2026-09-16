rule TTP_XOR_MULT_DOSStub_e2a7 {
  strings:
    $key_e2a7 = { b6 cf [2] c2 d7 [2] 85 d5 [2] c2 c4 [2] 8c c8 [2] 80 c2 [2] 97 c9 [2] 8c 87 [2] b1 }

  condition:
    any of them
}