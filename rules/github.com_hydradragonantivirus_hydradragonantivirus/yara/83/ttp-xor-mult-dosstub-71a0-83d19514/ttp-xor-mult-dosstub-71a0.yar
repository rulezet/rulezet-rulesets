rule TTP_XOR_MULT_DOSStub_71a0 {
  strings:
    $key_71a0 = { 25 c8 [2] 51 d0 [2] 16 d2 [2] 51 c3 [2] 1f cf [2] 13 c5 [2] 04 ce [2] 1f 80 [2] 22 }

  condition:
    any of them
}