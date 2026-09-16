rule TTP_XOR_MULT_DOSStub_62a0 {
  strings:
    $key_62a0 = { 36 c8 [2] 42 d0 [2] 05 d2 [2] 42 c3 [2] 0c cf [2] 00 c5 [2] 17 ce [2] 0c 80 [2] 31 }

  condition:
    any of them
}