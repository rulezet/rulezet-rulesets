rule TTP_XOR_MULT_DOSStub_52a7 {
  strings:
    $key_52a7 = { 06 cf [2] 72 d7 [2] 35 d5 [2] 72 c4 [2] 3c c8 [2] 30 c2 [2] 27 c9 [2] 3c 87 [2] 01 }

  condition:
    any of them
}