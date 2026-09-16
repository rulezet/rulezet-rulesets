rule TTP_XOR_MULT_DOSStub_57a7 {
  strings:
    $key_57a7 = { 03 cf [2] 77 d7 [2] 30 d5 [2] 77 c4 [2] 39 c8 [2] 35 c2 [2] 22 c9 [2] 39 87 [2] 04 }

  condition:
    any of them
}