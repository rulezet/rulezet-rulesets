rule TTP_XOR_MULT_DOSStub_54a7 {
  strings:
    $key_54a7 = { 00 cf [2] 74 d7 [2] 33 d5 [2] 74 c4 [2] 3a c8 [2] 36 c2 [2] 21 c9 [2] 3a 87 [2] 07 }

  condition:
    any of them
}