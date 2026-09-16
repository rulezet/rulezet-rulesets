rule TTP_XOR_MULT_DOSStub_12b6 {
  strings:
    $key_12b6 = { 46 de [2] 32 c6 [2] 75 c4 [2] 32 d5 [2] 7c d9 [2] 70 d3 [2] 67 d8 [2] 7c 96 [2] 41 }

  condition:
    any of them
}