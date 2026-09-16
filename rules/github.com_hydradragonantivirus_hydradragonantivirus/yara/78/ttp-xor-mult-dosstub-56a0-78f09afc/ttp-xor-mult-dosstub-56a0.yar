rule TTP_XOR_MULT_DOSStub_56a0 {
  strings:
    $key_56a0 = { 02 c8 [2] 76 d0 [2] 31 d2 [2] 76 c3 [2] 38 cf [2] 34 c5 [2] 23 ce [2] 38 80 [2] 05 }

  condition:
    any of them
}