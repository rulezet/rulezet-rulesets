rule TTP_XOR_MULT_DOSStub_52b6 {
  strings:
    $key_52b6 = { 06 de [2] 72 c6 [2] 35 c4 [2] 72 d5 [2] 3c d9 [2] 30 d3 [2] 27 d8 [2] 3c 96 [2] 01 }

  condition:
    any of them
}