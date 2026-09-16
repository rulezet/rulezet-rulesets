rule TTP_XOR_MULT_DOSStub_17b6 {
  strings:
    $key_17b6 = { 43 de [2] 37 c6 [2] 70 c4 [2] 37 d5 [2] 79 d9 [2] 75 d3 [2] 62 d8 [2] 79 96 [2] 44 }

  condition:
    any of them
}