rule TTP_XOR_MULT_DOSStub_07a7 {
  strings:
    $key_07a7 = { 53 cf [2] 27 d7 [2] 60 d5 [2] 27 c4 [2] 69 c8 [2] 65 c2 [2] 72 c9 [2] 69 87 [2] 54 }

  condition:
    any of them
}