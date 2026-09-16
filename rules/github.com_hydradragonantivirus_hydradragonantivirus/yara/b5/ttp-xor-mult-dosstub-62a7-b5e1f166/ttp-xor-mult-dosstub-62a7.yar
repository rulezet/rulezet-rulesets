rule TTP_XOR_MULT_DOSStub_62a7 {
  strings:
    $key_62a7 = { 36 cf [2] 42 d7 [2] 05 d5 [2] 42 c4 [2] 0c c8 [2] 00 c2 [2] 17 c9 [2] 0c 87 [2] 31 }

  condition:
    any of them
}