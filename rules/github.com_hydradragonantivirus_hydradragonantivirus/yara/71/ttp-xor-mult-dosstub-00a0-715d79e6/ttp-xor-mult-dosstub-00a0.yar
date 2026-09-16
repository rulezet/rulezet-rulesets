rule TTP_XOR_MULT_DOSStub_00a0 {
  strings:
    $key_00a0 = { 54 c8 [2] 20 d0 [2] 67 d2 [2] 20 c3 [2] 6e cf [2] 62 c5 [2] 75 ce [2] 6e 80 [2] 53 }

  condition:
    any of them
}