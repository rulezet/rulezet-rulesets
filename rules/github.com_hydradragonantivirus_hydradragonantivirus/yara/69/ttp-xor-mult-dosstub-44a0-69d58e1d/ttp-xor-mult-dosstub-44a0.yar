rule TTP_XOR_MULT_DOSStub_44a0 {
  strings:
    $key_44a0 = { 10 c8 [2] 64 d0 [2] 23 d2 [2] 64 c3 [2] 2a cf [2] 26 c5 [2] 31 ce [2] 2a 80 [2] 17 }

  condition:
    any of them
}