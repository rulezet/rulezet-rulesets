rule TTP_XOR_MULT_DOSStub_75a7 {
  strings:
    $key_75a7 = { 21 cf [2] 55 d7 [2] 12 d5 [2] 55 c4 [2] 1b c8 [2] 17 c2 [2] 00 c9 [2] 1b 87 [2] 26 }

  condition:
    any of them
}