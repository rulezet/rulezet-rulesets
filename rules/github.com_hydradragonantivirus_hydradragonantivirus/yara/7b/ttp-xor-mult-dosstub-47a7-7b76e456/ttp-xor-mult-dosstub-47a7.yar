rule TTP_XOR_MULT_DOSStub_47a7 {
  strings:
    $key_47a7 = { 13 cf [2] 67 d7 [2] 20 d5 [2] 67 c4 [2] 29 c8 [2] 25 c2 [2] 32 c9 [2] 29 87 [2] 14 }

  condition:
    any of them
}