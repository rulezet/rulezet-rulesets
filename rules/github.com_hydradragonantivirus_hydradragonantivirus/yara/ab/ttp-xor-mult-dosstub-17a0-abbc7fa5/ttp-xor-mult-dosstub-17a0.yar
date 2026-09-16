rule TTP_XOR_MULT_DOSStub_17a0 {
  strings:
    $key_17a0 = { 43 c8 [2] 37 d0 [2] 70 d2 [2] 37 c3 [2] 79 cf [2] 75 c5 [2] 62 ce [2] 79 80 [2] 44 }

  condition:
    any of them
}