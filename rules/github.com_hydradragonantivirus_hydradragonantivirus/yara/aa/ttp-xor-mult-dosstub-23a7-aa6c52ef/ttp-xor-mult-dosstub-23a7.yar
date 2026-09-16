rule TTP_XOR_MULT_DOSStub_23a7 {
  strings:
    $key_23a7 = { 77 cf [2] 03 d7 [2] 44 d5 [2] 03 c4 [2] 4d c8 [2] 41 c2 [2] 56 c9 [2] 4d 87 [2] 70 }

  condition:
    any of them
}