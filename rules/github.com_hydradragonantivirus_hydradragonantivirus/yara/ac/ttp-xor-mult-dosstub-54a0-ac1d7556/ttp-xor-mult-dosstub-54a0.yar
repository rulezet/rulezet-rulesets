rule TTP_XOR_MULT_DOSStub_54a0 {
  strings:
    $key_54a0 = { 00 c8 [2] 74 d0 [2] 33 d2 [2] 74 c3 [2] 3a cf [2] 36 c5 [2] 21 ce [2] 3a 80 [2] 07 }

  condition:
    any of them
}