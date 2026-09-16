rule TTP_XOR_MULT_DOSStub_56b6 {
  strings:
    $key_56b6 = { 02 de [2] 76 c6 [2] 31 c4 [2] 76 d5 [2] 38 d9 [2] 34 d3 [2] 23 d8 [2] 38 96 [2] 05 }

  condition:
    any of them
}