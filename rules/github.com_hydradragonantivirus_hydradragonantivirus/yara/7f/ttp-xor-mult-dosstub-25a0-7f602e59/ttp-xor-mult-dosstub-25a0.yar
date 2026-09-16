rule TTP_XOR_MULT_DOSStub_25a0 {
  strings:
    $key_25a0 = { 71 c8 [2] 05 d0 [2] 42 d2 [2] 05 c3 [2] 4b cf [2] 47 c5 [2] 50 ce [2] 4b 80 [2] 76 }

  condition:
    any of them
}