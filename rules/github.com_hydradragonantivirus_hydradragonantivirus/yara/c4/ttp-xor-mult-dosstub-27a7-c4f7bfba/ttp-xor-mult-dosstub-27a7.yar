rule TTP_XOR_MULT_DOSStub_27a7 {
  strings:
    $key_27a7 = { 73 cf [2] 07 d7 [2] 40 d5 [2] 07 c4 [2] 49 c8 [2] 45 c2 [2] 52 c9 [2] 49 87 [2] 74 }

  condition:
    any of them
}