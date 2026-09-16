rule TTP_XOR_MULT_DOSStub_01a0 {
  strings:
    $key_01a0 = { 55 c8 [2] 21 d0 [2] 66 d2 [2] 21 c3 [2] 6f cf [2] 63 c5 [2] 74 ce [2] 6f 80 [2] 52 }

  condition:
    any of them
}