rule TTP_XOR_MULT_DOSStub_42a0 {
  strings:
    $key_42a0 = { 16 c8 [2] 62 d0 [2] 25 d2 [2] 62 c3 [2] 2c cf [2] 20 c5 [2] 37 ce [2] 2c 80 [2] 11 }

  condition:
    any of them
}