rule TTP_XOR_MULT_DOSStub_36a0 {
  strings:
    $key_36a0 = { 62 c8 [2] 16 d0 [2] 51 d2 [2] 16 c3 [2] 58 cf [2] 54 c5 [2] 43 ce [2] 58 80 [2] 65 }

  condition:
    any of them
}