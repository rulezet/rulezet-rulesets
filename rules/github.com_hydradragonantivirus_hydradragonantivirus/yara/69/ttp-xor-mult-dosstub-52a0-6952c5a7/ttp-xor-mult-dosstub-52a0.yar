rule TTP_XOR_MULT_DOSStub_52a0 {
  strings:
    $key_52a0 = { 06 c8 [2] 72 d0 [2] 35 d2 [2] 72 c3 [2] 3c cf [2] 30 c5 [2] 27 ce [2] 3c 80 [2] 01 }

  condition:
    any of them
}