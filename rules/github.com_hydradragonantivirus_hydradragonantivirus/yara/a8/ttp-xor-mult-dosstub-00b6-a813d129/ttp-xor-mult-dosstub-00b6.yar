rule TTP_XOR_MULT_DOSStub_00b6 {
  strings:
    $key_00b6 = { 54 de [2] 20 c6 [2] 67 c4 [2] 20 d5 [2] 6e d9 [2] 62 d3 [2] 75 d8 [2] 6e 96 [2] 53 }

  condition:
    any of them
}