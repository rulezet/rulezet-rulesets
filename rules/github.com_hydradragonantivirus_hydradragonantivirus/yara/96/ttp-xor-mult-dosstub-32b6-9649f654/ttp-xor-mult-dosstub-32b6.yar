rule TTP_XOR_MULT_DOSStub_32b6 {
  strings:
    $key_32b6 = { 66 de [2] 12 c6 [2] 55 c4 [2] 12 d5 [2] 5c d9 [2] 50 d3 [2] 47 d8 [2] 5c 96 [2] 61 }

  condition:
    any of them
}