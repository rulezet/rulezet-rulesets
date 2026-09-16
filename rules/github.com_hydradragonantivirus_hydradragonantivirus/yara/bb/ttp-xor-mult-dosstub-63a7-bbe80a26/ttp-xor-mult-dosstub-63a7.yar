rule TTP_XOR_MULT_DOSStub_63a7 {
  strings:
    $key_63a7 = { 37 cf [2] 43 d7 [2] 04 d5 [2] 43 c4 [2] 0d c8 [2] 01 c2 [2] 16 c9 [2] 0d 87 [2] 30 }

  condition:
    any of them
}