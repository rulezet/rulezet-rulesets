rule TTP_XOR_MULT_DOSStub_21a7 {
  strings:
    $key_21a7 = { 75 cf [2] 01 d7 [2] 46 d5 [2] 01 c4 [2] 4f c8 [2] 43 c2 [2] 54 c9 [2] 4f 87 [2] 72 }

  condition:
    any of them
}