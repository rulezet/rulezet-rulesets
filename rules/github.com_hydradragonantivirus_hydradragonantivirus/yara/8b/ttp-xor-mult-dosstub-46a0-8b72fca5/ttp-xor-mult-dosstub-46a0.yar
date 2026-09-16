rule TTP_XOR_MULT_DOSStub_46a0 {
  strings:
    $key_46a0 = { 12 c8 [2] 66 d0 [2] 21 d2 [2] 66 c3 [2] 28 cf [2] 24 c5 [2] 33 ce [2] 28 80 [2] 15 }

  condition:
    any of them
}