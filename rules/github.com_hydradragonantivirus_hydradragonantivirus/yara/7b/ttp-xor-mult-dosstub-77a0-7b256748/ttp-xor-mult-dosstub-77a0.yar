rule TTP_XOR_MULT_DOSStub_77a0 {
  strings:
    $key_77a0 = { 23 c8 [2] 57 d0 [2] 10 d2 [2] 57 c3 [2] 19 cf [2] 15 c5 [2] 02 ce [2] 19 80 [2] 24 }

  condition:
    any of them
}