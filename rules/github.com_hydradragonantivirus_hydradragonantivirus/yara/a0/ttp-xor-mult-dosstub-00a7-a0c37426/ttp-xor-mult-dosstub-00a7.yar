rule TTP_XOR_MULT_DOSStub_00a7 {
  strings:
    $key_00a7 = { 54 cf [2] 20 d7 [2] 67 d5 [2] 20 c4 [2] 6e c8 [2] 62 c2 [2] 75 c9 [2] 6e 87 [2] 53 }

  condition:
    any of them
}