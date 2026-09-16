rule TTP_XOR_MULT_DOSStub_32a7 {
  strings:
    $key_32a7 = { 66 cf [2] 12 d7 [2] 55 d5 [2] 12 c4 [2] 5c c8 [2] 50 c2 [2] 47 c9 [2] 5c 87 [2] 61 }

  condition:
    any of them
}