rule TTP_XOR_MULT_DOSStub_40a7 {
  strings:
    $key_40a7 = { 14 cf [2] 60 d7 [2] 27 d5 [2] 60 c4 [2] 2e c8 [2] 22 c2 [2] 35 c9 [2] 2e 87 [2] 13 }

  condition:
    any of them
}