rule TTP_XOR_MULT_DOSStub_41b6 {
  strings:
    $key_41b6 = { 15 de [2] 61 c6 [2] 26 c4 [2] 61 d5 [2] 2f d9 [2] 23 d3 [2] 34 d8 [2] 2f 96 [2] 12 }

  condition:
    any of them
}