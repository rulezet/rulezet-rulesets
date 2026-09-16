rule TTP_XOR_MULT_DOSStub_02a7 {
  strings:
    $key_02a7 = { 56 cf [2] 22 d7 [2] 65 d5 [2] 22 c4 [2] 6c c8 [2] 60 c2 [2] 77 c9 [2] 6c 87 [2] 51 }

  condition:
    any of them
}