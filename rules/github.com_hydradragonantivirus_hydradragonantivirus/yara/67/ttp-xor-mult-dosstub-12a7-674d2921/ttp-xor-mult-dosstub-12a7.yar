rule TTP_XOR_MULT_DOSStub_12a7 {
  strings:
    $key_12a7 = { 46 cf [2] 32 d7 [2] 75 d5 [2] 32 c4 [2] 7c c8 [2] 70 c2 [2] 67 c9 [2] 7c 87 [2] 41 }

  condition:
    any of them
}