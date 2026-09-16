rule TTP_XOR_MULT_DOSStub_36a7 {
  strings:
    $key_36a7 = { 62 cf [2] 16 d7 [2] 51 d5 [2] 16 c4 [2] 58 c8 [2] 54 c2 [2] 43 c9 [2] 58 87 [2] 65 }

  condition:
    any of them
}