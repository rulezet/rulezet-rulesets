rule TTP_XOR_MULT_DOSStub_04a7 {
  strings:
    $key_04a7 = { 50 cf [2] 24 d7 [2] 63 d5 [2] 24 c4 [2] 6a c8 [2] 66 c2 [2] 71 c9 [2] 6a 87 [2] 57 }

  condition:
    any of them
}