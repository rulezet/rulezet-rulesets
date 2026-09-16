rule TTP_XOR_MULT_DOSStub_70a0 {
  strings:
    $key_70a0 = { 24 c8 [2] 50 d0 [2] 17 d2 [2] 50 c3 [2] 1e cf [2] 12 c5 [2] 05 ce [2] 1e 80 [2] 23 }

  condition:
    any of them
}