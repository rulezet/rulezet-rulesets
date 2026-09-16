rule TTP_XOR_MULT_DOSStub_31a7 {
  strings:
    $key_31a7 = { 65 cf [2] 11 d7 [2] 56 d5 [2] 11 c4 [2] 5f c8 [2] 53 c2 [2] 44 c9 [2] 5f 87 [2] 62 }

  condition:
    any of them
}