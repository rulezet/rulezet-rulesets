rule TTP_XOR_MULT_DOSStub_04b6 {
  strings:
    $key_04b6 = { 50 de [2] 24 c6 [2] 63 c4 [2] 24 d5 [2] 6a d9 [2] 66 d3 [2] 71 d8 [2] 6a 96 [2] 57 }

  condition:
    any of them
}