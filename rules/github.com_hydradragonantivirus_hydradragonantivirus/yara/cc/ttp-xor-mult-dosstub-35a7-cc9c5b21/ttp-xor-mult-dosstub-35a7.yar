rule TTP_XOR_MULT_DOSStub_35a7 {
  strings:
    $key_35a7 = { 61 cf [2] 15 d7 [2] 52 d5 [2] 15 c4 [2] 5b c8 [2] 57 c2 [2] 40 c9 [2] 5b 87 [2] 66 }

  condition:
    any of them
}